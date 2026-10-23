/**
 * `opena2a shield init` environment detection looks up each cloud CLI only in
 * PATH's absolute directories and starts it by its absolute path.
 *
 * An empty or relative PATH entry (`.`, a bare `bin`, `node_modules/.bin`, or
 * the empty entry a leading, trailing or doubled separator leaves) is resolved
 * against the directory the CLI was started in — which, for `shield init`, is
 * the tree being scanned. Before this fix, detection found a CLI with `which`
 * and then started it by bare name, so a program placed in such an entry's
 * directory was looked up, run, and listed. These cases pin that it is not.
 *
 * The version probe runs in a new, empty directory made for the run under the
 * system temporary directory and removed afterwards, whatever HOME holds;
 * when that directory cannot be made, no version command is started and the
 * CLI is listed with no version and the reason.
 *
 * Every stub is written at run time into an `mkdtemp` directory and uses only
 * shell builtins (`echo`, redirection, `pwd -P`), so it needs nothing on the
 * narrowed PATH. No network, no CLI installed on the test machine is started.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, isAbsolute, join, sep } from 'node:path';

let root: string;
let originalCwd: string;
let realWhich: string;

function writeExecutable(filePath: string, body: string): void {
  writeFileSync(filePath, body);
  chmodSync(filePath, 0o755);
}

/**
 * An absolute scratch directory on PATH, a home, and a project to run in. The
 * absolute directory carries a `which` link: the pre-fix detector finds each
 * CLI with `which`, so without it the pre-fix path never reaches its bare-name
 * start and these cells could not prove anything. The fix starts no `which`.
 */
function layout(): { absoluteDir: string; home: string; project: string } {
  const absoluteDir = join(root, 'absolute');
  const home = join(root, 'home');
  const project = join(root, 'project');
  for (const dir of [absoluteDir, home, project]) mkdirSync(dir, { recursive: true });
  symlinkSync(realWhich, join(absoluteDir, 'which'));
  return { absoluteDir, home, project };
}

async function detect(targetDir: string) {
  const { detectEnvironment } = await import('../../src/shield/detect.js');
  return detectEnvironment(targetDir);
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'shield-detect-abs-'));
  originalCwd = process.cwd();
  const found = (process.env.PATH ?? '')
    .split(delimiter)
    .filter((dir) => isAbsolute(dir))
    .map((dir) => join(dir, 'which'))
    .find((file) => existsSync(file));
  if (!found) throw new Error('no `which` on PATH to stand in for the pre-fix detector');
  realWhich = found;
  vi.resetModules();
});

afterEach(() => {
  process.chdir(originalCwd);
  vi.unstubAllEnvs();
  vi.resetModules();
  rmSync(root, { recursive: true, force: true });
});

describe('shield init environment detection resolves each CLI through PATH\'s absolute directories', () => {
  // (a) A relative PATH entry (`bin`) holding an executable named like a probed
  // CLI is not searched: the planted program is neither run nor listed.
  it('does not run or list a CLI reachable only through a relative PATH entry', async () => {
    const { absoluteDir, home, project } = layout();
    mkdirSync(join(project, 'bin'));
    const marker = join(root, 'kubectl-ran.marker');
    writeExecutable(
      join(project, 'bin', 'kubectl'),
      `#!/bin/sh\necho ran > '${marker}'\necho 'Client Version: v1.33.0'\n`,
    );
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', `${absoluteDir}${delimiter}bin`);

    const scan = await detect(project);

    expect(existsSync(marker), 'the planted kubectl must not run').toBe(false);
    expect(scan.clis.map((c) => c.name)).not.toContain('kubectl');
  });

  // (b) The empty entry a trailing separator leaves (resolved against the
  // working directory) is not searched either.
  it('does not run or list a CLI reachable only through the empty entry a trailing separator leaves', async () => {
    const { absoluteDir, home, project } = layout();
    const marker = join(root, 'terraform-ran.marker');
    writeExecutable(
      join(project, 'terraform'),
      `#!/bin/sh\necho ran > '${marker}'\necho 'Terraform v1.9.0'\n`,
    );
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', `${absoluteDir}${delimiter}`);

    const scan = await detect(project);

    expect(existsSync(marker), 'the planted terraform must not run').toBe(false);
    expect(scan.clis.map((c) => c.name)).not.toContain('terraform');
  });

  // (c) Control: a CLI in an absolute PATH directory is still found, by its
  // absolute path, and its version is read.
  it('lists a CLI found in an absolute PATH directory, by its absolute path and version', async () => {
    const { absoluteDir, home, project } = layout();
    writeExecutable(join(absoluteDir, 'gh'), `#!/bin/sh\necho 'gh version 2.99.0 (2026-10-22)'\n`);
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', absoluteDir);

    const scan = await detect(project);

    const gh = scan.clis.find((c) => c.name === 'gh');
    expect(gh, 'gh in an absolute PATH directory is detected').toBeDefined();
    expect(gh!.path).toBe(join(absoluteDir, 'gh'));
    expect(gh!.version).toBe('gh version 2.99.0 (2026-10-22)');
  });

  // (d) The version probe runs with a PATH of only absolute directories and
  // outside the directory it was started in, so the probed program's own
  // lookups cannot reach a relative entry or the scanned tree.
  it('runs the version probe with no relative PATH entry and outside the directory it was started in', async () => {
    const { absoluteDir, home, project } = layout();
    const captureFile = join(root, 'gh-probe-env.txt');
    writeExecutable(
      join(absoluteDir, 'gh'),
      `#!/bin/sh\n{ echo "PATH=$PATH"; echo "PWD=$(pwd -P)"; } > '${captureFile}'\necho 'gh version 2.99.0'\n`,
    );
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', `${absoluteDir}${delimiter}bin`);

    await detect(project);

    const captured = readFileSync(captureFile, 'utf-8').split('\n');
    const probePath = (captured.find((l) => l.startsWith('PATH=')) ?? '').slice('PATH='.length);
    const probeCwd = (captured.find((l) => l.startsWith('PWD=')) ?? '').slice('PWD='.length);

    const entries = probePath.split(delimiter);
    expect(entries, 'the relative entry is gone from the probe PATH').not.toContain('bin');
    expect(entries.every((dir) => dir !== '' && isAbsolute(dir)), `probe PATH = ${probePath}`).toBe(true);
    expect(probeCwd, 'the probe did not run in the scanned tree').not.toBe(realpathSync(project));
    expect(probeCwd, 'the probe did not run in the home directory').not.toBe(realpathSync(home));
    expect(probeCwd.startsWith(realpathSync(tmpdir()) + sep), `the probe ran in ${probeCwd}`).toBe(true);
    expect(existsSync(probeCwd), 'the probe directory is removed when detection returns').toBe(false);
  });

  // (e) Whatever HOME holds (empty, naming a directory that does not exist,
  // or the directory shield init was started in), the version probe runs in
  // a new, empty directory under the system temporary directory, never the
  // start directory or HOME, and the version is read (#546).
  it.each([
    ['empty', (_r: string, _project: string) => ''],
    ['naming a missing directory', (r: string, _project: string) => join(r, 'missing-home')],
    ['equal to the start directory', (_r: string, project: string) => project],
  ])('runs the version probe outside the start directory and HOME, and reads the version, with HOME %s', async (_label, homeOf) => {
    const { absoluteDir, project } = layout();
    const captureFile = join(root, 'gh-probe-cwd.txt');
    writeExecutable(
      join(absoluteDir, 'gh'),
      '#!/bin/sh\n' +
      `{ echo "PWD=$(pwd -P)"; for f in * .[!.]* ..?*; do if [ -e "$f" ]; then echo "ENTRY=$f"; fi; done; } > '${captureFile}'\n` +
      "echo 'gh version 2.99.0'\n",
    );
    const home = homeOf(root, project);
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', absoluteDir);

    const scan = await detect(project);

    expect(existsSync(captureFile), 'the version probe ran').toBe(true);
    const captured = readFileSync(captureFile, 'utf-8').split('\n');
    const probeCwd = (captured.find((l) => l.startsWith('PWD=')) ?? '').slice('PWD='.length);
    expect(probeCwd, 'the probe did not run in the start directory').not.toBe(realpathSync(project));
    if (home !== '' && existsSync(home)) expect(probeCwd, 'the probe did not run in HOME').not.toBe(realpathSync(home));
    expect(probeCwd.startsWith(realpathSync(tmpdir()) + sep), `the probe ran in ${probeCwd}`).toBe(true);
    expect(existsSync(probeCwd), 'the probe directory is removed when detection returns').toBe(false);
    expect(captured.filter((l) => l.startsWith('ENTRY=')), 'the probe directory was empty').toEqual([]);
    const gh = scan.clis.find((c) => c.name === 'gh');
    expect(gh?.version).toBe('gh version 2.99.0');
    expect(gh?.versionNotRead).toBeUndefined();
  });

  // (f) When no empty directory can be made for the probe, nothing falls back
  // to HOME or the start directory: no version command is started, and the
  // CLI is still listed, with no version and the reason.
  it.each([
    ['names a missing directory', (r: string) => join(r, 'missing-tmp')],
    ['is a relative path', (_r: string) => 'tmp'],
  ])('starts no version probe, and lists the CLI with no version and a reason, when the temporary directory %s', async (_label, tmpOf) => {
    const { absoluteDir, home, project } = layout();
    const marker = join(root, 'gh-ran.marker');
    writeExecutable(join(absoluteDir, 'gh'), `#!/bin/sh\necho ran > '${marker}'\necho 'gh version 2.99.0'\n`);
    // A relative temporary directory names a directory that exists, in the start directory.
    mkdirSync(join(project, 'tmp'));
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', absoluteDir);
    const { detectEnvironment } = await import('../../src/shield/detect.js');
    vi.stubEnv('TMPDIR', tmpOf(root));

    const scan = detectEnvironment(project);

    expect(existsSync(marker), 'no version command may start').toBe(false);
    const gh = scan.clis.find((c) => c.name === 'gh');
    expect(gh, 'gh is still listed').toBeDefined();
    expect(gh!.path).toBe(join(absoluteDir, 'gh'));
    expect(gh!.version).toBeNull();
    expect(gh!.versionNotRead).toMatch(/working directory/);
  });
});

describe('the version probe refuses a working directory it cannot use', () => {
  // A working directory that is empty, relative or missing is an error the
  // caller sees; it is never dropped, which would start the program in this
  // process's working directory, and nothing is started.
  it.each([
    ['empty', (_r: string) => ''],
    ['relative', (_r: string) => 'project'],
    ['naming a missing directory', (r: string) => join(r, 'missing')],
  ])('throws and starts nothing for a working directory that is %s', async (_label, cwdOf) => {
    const { absoluteDir, project } = layout();
    const marker = join(root, 'probe-ran.marker');
    const stub = join(absoluteDir, 'probe');
    writeExecutable(stub, `#!/bin/sh\necho ran > '${marker}'\necho ok\n`);
    process.chdir(root);
    const { tryExecFile } = await import('../../src/shield/detect.js');

    expect(() => tryExecFile(stub, [], 5_000, { PATH: absoluteDir }, cwdOf(root))).toThrow(/working directory/);
    expect(existsSync(marker), 'nothing is started').toBe(false);
    // Control: an existing absolute directory starts the program there.
    expect(tryExecFile(stub, [], 5_000, { PATH: absoluteDir }, project)).toBe('ok');
    expect(existsSync(marker)).toBe(true);
  });
});
