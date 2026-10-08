/**
 * `opena2a guard resign` answered at a real terminal.
 *
 * The confirm prompt used to close its readline interface before resolving,
 * so readline's synchronous 'close' settled the answer as false first: a "y"
 * typed at a terminal printed "Re-sign cancelled." and exited 1, and the
 * published fix path for a changed monitored file never completed. The stream
 * tests in guard-snapshots.test.ts and util/confirm.test.ts drive the prompt
 * in-process; this suite drives the built `dist/index.js` under a
 * pseudo-terminal, the way a person runs it, and then checks the store with
 * `opena2a guard verify`.
 *
 * The pseudo-terminal comes from Python's standard `pty` module, which works
 * the same on Linux and macOS without a native Node dependency. The suite is
 * skipped where `python3` with `pty` is not available.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const CLI_PATH = path.resolve(__dirname, '../../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

// Runs argv[2:] on the slave side of a new pseudo-terminal, waits for the
// "[y/N]" prompt, types argv[1] followed by Return, and copies everything the
// command wrote to its terminal to stdout. Exits with the command's exit code,
// 97 if the child's stdin/stdout are not a terminal, or 98 if the prompt never
// appeared.
const PTY_DRIVER = String.raw`
import os, pty, select, sys, time
answer = sys.argv[1].encode()
cmd = sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    if not (os.isatty(0) and os.isatty(1)):
        os._exit(97)
    os.execvp(cmd[0], cmd)
out = b''
sent = False
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    ready, _, _ = select.select([fd], [], [], 0.5)
    if not ready:
        continue
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    out += chunk
    if not sent and b'[y/N]' in out:
        os.write(fd, answer + b'\r')
        sent = True
else:
    os.kill(pid, 9)
_, status = os.waitpid(pid, 0)
sys.stdout.write(out.decode('utf-8', 'replace'))
sys.stdout.flush()
code = os.waitstatus_to_exitcode(status)
sys.exit(code if sent or code == 97 else 98)
`;

const hasPty =
  process.platform !== 'win32' &&
  spawnSync('python3', ['-I', '-c', 'import pty, select'], { stdio: 'ignore' }).status === 0;

describe.skipIf(!hasPty)('guard resign at a terminal (pty)', () => {
  let workDir: string;
  let projectDir: string;
  let childEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-resign-pty-'));
    projectDir = path.join(workDir, 'project');
    const homeDir = path.join(workDir, 'home');
    fs.mkdirSync(projectDir);
    fs.mkdirSync(homeDir);
    childEnv = {
      ...process.env,
      HOME: homeDir,
      XDG_CONFIG_HOME: path.join(homeDir, '.config'),
      OPENA2A_TELEMETRY: 'off',
      NO_COLOR: '1',
      NODE_OPTIONS: '',
    };
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  function runCli(args: string[]): { status: number; output: string } {
    const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
      encoding: 'utf8',
      timeout: 30000,
      env: childEnv,
    });
    return {
      status: res.status ?? 1,
      output: ((res.stdout ?? '') + (res.stderr ?? '')).replace(STRIP_ANSI, ''),
    };
  }

  function resignAtTerminal(answer: string): { status: number; output: string } {
    const res = spawnSync(
      'python3',
      ['-I', '-c', PTY_DRIVER, answer, process.execPath, CLI_PATH, 'guard', 'resign', '--dir', projectDir],
      { encoding: 'utf8', timeout: 45000, env: childEnv },
    );
    return {
      status: res.status ?? 1,
      output: ((res.stdout ?? '') + (res.stderr ?? '')).replace(STRIP_ANSI, ''),
    };
  }

  function signThenChange(): string {
    const manifest = path.join(projectDir, 'package.json');
    fs.writeFileSync(manifest, '{"name":"original"}');
    expect(runCli(['guard', 'sign', '--dir', projectDir]).status).toBe(0);
    fs.writeFileSync(manifest, '{"name":"modified"}');
    const before = runCli(['guard', 'verify', '--dir', projectDir]);
    expect(before.status).toBe(1);
    return fs.readFileSync(path.join(projectDir, '.opena2a/guard/signatures.json'), 'utf-8');
  }

  it('a typed y re-signs the changed file, and guard verify then exits 0', () => {
    signThenChange();

    const resign = resignAtTerminal('y');
    expect(resign.output).toContain('Confirm re-sign? [y/N]');
    expect(resign.output).toContain('Re-signed 1 file.');
    expect(resign.output).not.toContain('Re-sign cancelled.');
    expect(resign.status).toBe(0);

    const verify = runCli(['guard', 'verify', '--dir', projectDir]);
    expect(verify.output).toContain('0 tampered');
    expect(verify.status).toBe(0);
  }, 120000);

  it('a typed n cancels, leaves the store unchanged, and guard verify still exits 1', () => {
    const storeBefore = signThenChange();

    const resign = resignAtTerminal('n');
    expect(resign.output).toContain('Confirm re-sign? [y/N]');
    expect(resign.output).toContain('Re-sign cancelled.');
    expect(resign.output).not.toContain('Re-signed');
    expect(resign.status).toBe(1);
    expect(fs.readFileSync(path.join(projectDir, '.opena2a/guard/signatures.json'), 'utf-8')).toBe(storeBefore);

    expect(runCli(['guard', 'verify', '--dir', projectDir]).status).toBe(1);
  }, 120000);
});
