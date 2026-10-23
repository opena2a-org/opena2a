/**
 * `getShieldStatus` (reached from `opena2a review`, `init`, `status` and
 * `shield status`) looks each helper tool up only in PATH's absolute
 * directories and starts it by that absolute path, with a probe environment
 * whose PATH holds only absolute directories, in an empty working directory
 * made for the run.
 *
 * An empty or relative PATH entry (`.`, a bare `bin`, `node_modules/.bin`, or
 * the empty entry a leading, trailing or doubled separator leaves) is resolved
 * against the directory the command was started in. These cases pin that a
 * program placed there is neither looked up nor started, and that a helper in
 * an absolute PATH directory still is.
 *
 * Every stub is written at run time into an `mkdtemp` directory and uses only
 * shell builtins (`echo`, `test`, redirection, `pwd -P`), so it needs nothing
 * on the narrowed PATH. PATH holds only scratch directories, so no tool
 * installed on the test machine is started. No network.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, isAbsolute, join, sep } from 'node:path';

/** The helpers status.ts looks up or starts, and the lookup tool it used to start. */
const HELPERS = ['which', 'secretless-ai', 'hackmyagent', 'opena2a'];

let root: string;
let markers: string;
let originalCwd: string;
let realWhich: string;

function writeExecutable(filePath: string, body: string): void {
  writeFileSync(filePath, body);
  chmodSync(filePath, 0o755);
}

/** A stub that records that it ran and answers like the helper it is named after. */
function plantMarkerStub(dir: string, name: string): void {
  mkdirSync(dir, { recursive: true });
  writeExecutable(
    join(dir, name),
    `#!/bin/sh\necho ran > '${join(markers, `${name}.ran`)}'\necho "${join(dir, '$1')}"\necho '9.9.9'\n`,
  );
}

function markersWritten(): string[] {
  return readdirSync(markers).sort();
}

function layout(): { absoluteDir: string; home: string; project: string } {
  const absoluteDir = join(root, 'absolute');
  const home = join(root, 'home');
  const project = join(root, 'project');
  for (const dir of [absoluteDir, home, project, markers]) mkdirSync(dir, { recursive: true });
  return { absoluteDir, home, project };
}

async function shieldStatus() {
  const { getShieldStatus } = await import('../../src/shield/status.js');
  return getShieldStatus();
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'shield-status-abs-'));
  markers = join(root, 'markers');
  originalCwd = process.cwd();
  const found = (process.env.PATH ?? '')
    .split(delimiter)
    .filter((dir) => isAbsolute(dir))
    .map((dir) => join(dir, 'which'))
    .find((file) => existsSync(file));
  if (!found) throw new Error('no `which` on PATH to stand in for a lookup tool in the controls');
  realWhich = found;
  vi.resetModules();
});

afterEach(() => {
  process.chdir(originalCwd);
  vi.unstubAllEnvs();
  vi.resetModules();
  rmSync(root, { recursive: true, force: true });
});

describe('shield status starts helper tools only by absolute path from PATH\'s absolute directories', () => {
  // (a) The working directory holds a program named like each helper, and
  // PATH is an absolute directory without them plus an empty entry, which is
  // resolved against the working directory. None of them runs.
  it.each([
    ['trailing', (abs: string) => `${abs}${delimiter}`],
    ['leading', (abs: string) => `${delimiter}${abs}`],
    ['doubled', (abs: string) => `${abs}${delimiter}${delimiter}${abs}`],
  ])('starts no program reachable only through the empty entry a %s separator leaves', async (_form, pathOf) => {
    const { absoluteDir, home, project } = layout();
    for (const name of HELPERS) plantMarkerStub(project, name);
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', pathOf(absoluteDir));

    const status = await shieldStatus();

    expect(markersWritten(), 'no planted helper may run').toEqual([]);
    const secretless = status.tools.find((t) => t.name === 'Secretless')!;
    expect(secretless.installed).toBe(false);
    expect(secretless.version).toBeNull();
    expect(status.tools.find((t) => t.name === 'Registry')!.keyMetric).toBe('not available');
  });

  // (b) The same with a relative entry: `.`, a bare `bin`, `node_modules/.bin`.
  it.each(['.', 'bin', join('node_modules', '.bin')])(
    'starts no program reachable only through the relative PATH entry %s',
    async (relative) => {
      const { absoluteDir, home, project } = layout();
      for (const name of HELPERS) plantMarkerStub(join(project, relative), name);
      process.chdir(project);
      vi.stubEnv('HOME', home);
      vi.stubEnv('PATH', `${absoluteDir}${delimiter}${relative}`);

      const status = await shieldStatus();

      expect(markersWritten(), 'no planted helper may run').toEqual([]);
      expect(status.tools.find((t) => t.name === 'Secretless')!.installed).toBe(false);
      expect(status.tools.find((t) => t.name === 'Registry')!.keyMetric).toBe('not available');
    },
  );

  // (d) The version probe runs in a new, empty directory under the system
  // temporary directory, removed afterwards: never the directory the command
  // was started in and never HOME, whatever HOME holds.
  it.each([
    ['empty', (_root: string, _project: string) => ''],
    ['naming a missing directory', (r: string, _project: string) => join(r, 'missing-home')],
    ['equal to the start directory', (_root: string, project: string) => project],
  ])('runs the version probe outside the start directory and HOME, with HOME %s', async (_label, homeOf) => {
    const { absoluteDir, project } = layout();
    symlinkSync(realWhich, join(absoluteDir, 'which'));
    const capture = join(root, 'secretless-probe.txt');
    writeExecutable(
      join(absoluteDir, 'secretless-ai'),
      '#!/bin/sh\n' +
      `{ echo "PWD=$(pwd -P)"; echo "PATH=$PATH"; echo "ARG0=$0"; echo "PLANTED=\${GITHUB_TOKEN-unset}"; ` +
      'for f in * .[!.]* ..?*; do if [ -e "$f" ]; then echo "ENTRY=$f"; fi; done; } > ' + `'${capture}'\n` +
      "echo '9.9.9'\n",
    );
    const home = homeOf(root, project);
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', `${absoluteDir}${delimiter}bin`);
    vi.stubEnv('GITHUB_TOKEN', 'PLANTED-status-probe');

    const status = await shieldStatus();

    const lines = readFileSync(capture, 'utf-8').split('\n');
    const value = (key: string) => (lines.find((l) => l.startsWith(`${key}=`)) ?? '').slice(key.length + 1);
    const probeCwd = value('PWD');
    expect(probeCwd, 'the probe did not run in the start directory').not.toBe(realpathSync(project));
    if (home !== '' && existsSync(home)) expect(probeCwd, 'the probe did not run in HOME').not.toBe(realpathSync(home));
    expect(probeCwd.startsWith(realpathSync(tmpdir()) + sep), `probe ran in ${probeCwd}`).toBe(true);
    expect(existsSync(probeCwd), 'the probe directory is removed after the run').toBe(false);
    expect(lines.filter((l) => l.startsWith('ENTRY=')), 'the probe directory was empty').toEqual([]);
    const entries = value('PATH').split(delimiter);
    expect(entries.every((dir) => dir !== '' && isAbsolute(dir)), `probe PATH = ${value('PATH')}`).toBe(true);
    expect(entries).not.toContain('bin');
    expect(value('ARG0'), 'started by its absolute path').toBe(join(absoluteDir, 'secretless-ai'));
    expect(value('PLANTED'), 'the probe environment drops credential-named variables').toBe('unset');
    expect(status.tools.find((t) => t.name === 'Secretless')!.version).toBe('9.9.9');
  });

  // (f) Controls: a helper in an absolute PATH directory is found, started by
  // its absolute path and shown as installed; the registry presence is a
  // lookup that starts nothing.
  it('shows a helper installed in an absolute PATH directory as installed, and finds the registry CLI without starting it', async () => {
    const { absoluteDir, home, project } = layout();
    symlinkSync(realWhich, join(absoluteDir, 'which'));
    writeExecutable(join(absoluteDir, 'secretless-ai'), "#!/bin/sh\necho '9.9.9'\n");
    plantMarkerStub(absoluteDir, 'opena2a');
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', absoluteDir);

    const status = await shieldStatus();

    const secretless = status.tools.find((t) => t.name === 'Secretless')!;
    expect(secretless.installed).toBe(true);
    expect(secretless.version).toBe('9.9.9');
    expect(status.tools.find((t) => t.name === 'Registry')!.keyMetric).toBe('available');
    expect(markersWritten(), 'finding the registry CLI starts nothing').toEqual([]);
  });
});
