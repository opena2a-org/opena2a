/**
 * The shield model-CLI backend looks `claude` up only in PATH's absolute
 * directories and starts it by that absolute path, with the `claude` contract
 * environment, a PATH of only absolute directories, and an empty working
 * directory made for the call.
 *
 * An empty or relative PATH entry is resolved against the directory the
 * command was started in, so a `claude` reachable only through one is never
 * chosen as the backend and never started.
 *
 * Stubs only: every `claude` here is a shell script written at run time into
 * an `mkdtemp` directory that uses only shell builtins, and PATH holds only
 * scratch directories, so no model CLI installed on the test machine can be
 * found or started. ANTHROPIC_API_KEY is unset, so the API backend is never
 * chosen either. No network.
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
 * An absolute scratch directory for PATH, a home, and a project to run in.
 * The absolute directory carries a `which` link so that a backend that finds
 * the model CLI with `which` reaches its bare-name start in these cells; the
 * backend under test starts no `which`.
 */
function layout(): { absoluteDir: string; home: string; project: string } {
  const absoluteDir = join(root, 'absolute');
  const home = join(root, 'home');
  const project = join(root, 'project');
  for (const dir of [absoluteDir, home, project]) mkdirSync(dir, { recursive: true });
  symlinkSync(realWhich, join(absoluteDir, 'which'));
  return { absoluteDir, home, project };
}

async function backend() {
  return import('../../src/shield/llm-backend.js');
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'shield-llm-abs-'));
  originalCwd = process.cwd();
  const found = (process.env.PATH ?? '')
    .split(delimiter)
    .filter((dir) => isAbsolute(dir))
    .map((dir) => join(dir, 'which'))
    .find((file) => existsSync(file));
  if (!found) throw new Error('no `which` on PATH to stand in for a lookup tool');
  realWhich = found;
  vi.stubEnv('CLAUDECODE', undefined);
  vi.stubEnv('ANTHROPIC_API_KEY', undefined);
  vi.resetModules();
});

afterEach(() => {
  process.chdir(originalCwd);
  vi.unstubAllEnvs();
  vi.resetModules();
  rmSync(root, { recursive: true, force: true });
});

describe('the shield model-CLI backend starts the model CLI only by absolute path from PATH\'s absolute directories', () => {
  // (c) A model-CLI stub reachable only through a relative or empty PATH
  // entry is not chosen as the backend, and nothing is started.
  it.each([
    ['the relative entry bin', 'bin'],
    ['the relative entry .', '.'],
    ['the empty entry a trailing separator leaves', ''],
  ])('does not choose or start a model CLI reachable only through %s', async (_label, entry) => {
    const { absoluteDir, home, project } = layout();
    const marker = join(root, 'claude-ran.marker');
    const stubDir = join(project, entry);
    mkdirSync(stubDir, { recursive: true });
    writeExecutable(
      join(stubDir, 'claude'),
      `#!/bin/sh\necho ran > '${marker}'\necho '{"result":"planted"}'\n`,
    );
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', `${absoluteDir}${delimiter}${entry}`);

    const { isClaudeCodeAvailable, detectBackend, callClaudeCode, callLlm } = await backend();

    expect(isClaudeCodeAvailable(), 'claude is not found through a relative or empty entry').toBe(false);
    expect((await detectBackend()).backend).toBe('none');
    expect(callClaudeCode('system', 'user', 10), 'a direct call starts nothing').toBeNull();
    expect(await callLlm('system', 'user', 10)).toBeNull();
    expect(existsSync(marker), 'the planted claude must not run').toBe(false);
  });

  // Control and (d): a claude in an absolute PATH directory is chosen and
  // started by its absolute path, with a PATH of only absolute directories,
  // in a new, empty directory under the system temporary directory that is
  // removed afterwards: never the directory the command was started in and
  // never HOME, whatever HOME holds.
  it.each([
    ['set to its own directory', (r: string, _project: string) => join(r, 'home')],
    ['empty', (_r: string, _project: string) => ''],
    ['naming a missing directory', (r: string, _project: string) => join(r, 'missing-home')],
    ['equal to the start directory', (_r: string, project: string) => project],
  ])('starts a model CLI found in an absolute PATH directory by that path, outside the start directory and HOME, with HOME %s', async (_label, homeOf) => {
    const { absoluteDir, project } = layout();
    const capture = join(root, 'claude-call.txt');
    writeExecutable(
      join(absoluteDir, 'claude'),
      '#!/bin/sh\n' +
      '{ echo "PWD=$(pwd -P)"; echo "PATH=$PATH"; echo "ARG0=$0"; ' +
      'for f in * .[!.]* ..?*; do if [ -e "$f" ]; then echo "ENTRY=$f"; fi; done; } > ' + `'${capture}'\n` +
      `echo '{"result":"stub-ok"}'\n`,
    );
    const home = homeOf(root, project);
    process.chdir(project);
    vi.stubEnv('HOME', home);
    vi.stubEnv('PATH', `${absoluteDir}${delimiter}bin`);

    const { isClaudeCodeAvailable, detectBackend, callClaudeCode } = await backend();

    expect(isClaudeCodeAvailable()).toBe(true);
    expect((await detectBackend()).backend).toBe('claude-code');
    const response = callClaudeCode('system', 'user', 10);
    expect(response?.text).toBe('stub-ok');

    const lines = readFileSync(capture, 'utf-8').split('\n');
    const value = (key: string) => (lines.find((l) => l.startsWith(`${key}=`)) ?? '').slice(key.length + 1);
    const callCwd = value('PWD');
    expect(callCwd, 'claude did not run in the start directory').not.toBe(realpathSync(project));
    if (home !== '' && existsSync(home)) expect(callCwd, 'claude did not run in HOME').not.toBe(realpathSync(home));
    expect(callCwd.startsWith(realpathSync(tmpdir()) + sep), `claude ran in ${callCwd}`).toBe(true);
    expect(existsSync(callCwd), 'the call directory is removed after the call').toBe(false);
    expect(lines.filter((l) => l.startsWith('ENTRY=')), 'the call directory was empty').toEqual([]);
    const entries = value('PATH').split(delimiter);
    expect(entries.every((dir) => dir !== '' && isAbsolute(dir)), `claude PATH = ${value('PATH')}`).toBe(true);
    expect(entries).not.toContain('bin');
    expect(value('ARG0'), 'started by its absolute path').toBe(join(absoluteDir, 'claude'));
  });
});
