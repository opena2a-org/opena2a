/**
 * cli-ui 0.5.2 — `--version` stream split.
 *
 * The version output is rendered via `versionLineParts` and a manual
 * `option:version` handler (not Commander's `.version()`, which writes
 * everything to stdout). The bare `opena2a x.y.z` must land on stdout as a
 * single parseable line; the telemetry disclosure must land on stderr.
 *
 * Exercises the built `dist/index.js` end-to-end.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';

const CLI_PATH = resolve(__dirname, '../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

// @opena2a/telemetry's env opt-out is ONE-WAY: loadConfig computes
// `enabled = !envDisabled && fileEnabled`, so OPENA2A_TELEMETRY=on can never
// force telemetry ON over a persisted ~/.config/opena2a/telemetry.json that
// says enabled:false. This suite spawns the real CLI and asserts on that
// disclosure line, so without isolation it silently reads the HOST's opt-out
// state instead of the "on" scenario it means to test — green on CI (fresh
// runner, no config file) and red on any machine where telemetry is genuinely
// opted out. Isolating XDG_CONFIG_HOME to a fresh directory makes it
// deterministic: no telemetry.json there, so loadConfig's `fileEnabled ?? true`
// default applies. Same fix as ai-trust's copy of this suite.
let xdgConfigHome: string;

beforeAll(() => {
  xdgConfigHome = mkdtempSync(join(tmpdir(), 'opena2a-version-test-'));
});

afterAll(() => {
  rmSync(xdgConfigHome, { recursive: true, force: true });
});

function runVersion(flag: string, telemetry = 'on'): { stdout: string; stderr: string; status: number } {
  const res = spawnSync(process.execPath, [CLI_PATH, flag], {
    encoding: 'utf8',
    timeout: 20000,
    env: {
      ...process.env,
      NODE_OPTIONS: '',
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: telemetry,
      XDG_CONFIG_HOME: xdgConfigHome,
    },
  });
  return {
    stdout: (res.stdout ?? '').replace(STRIP_ANSI, ''),
    stderr: (res.stderr ?? '').replace(STRIP_ANSI, ''),
    status: res.status ?? 1,
  };
}

describe('--version stream split (cli-ui 0.5.2)', () => {
  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  it('stdout is a single clean `opena2a x.y.z` line, telemetry goes to stderr', () => {
    if (!existsSync(CLI_PATH)) return;
    const { stdout, stderr, status } = runVersion('--version');
    expect(status).toBe(0);

    const stdoutLines = stdout.trim().split('\n').filter((l) => l.length > 0);
    expect(stdoutLines).toHaveLength(1);
    expect(stdoutLines[0]).toMatch(/^opena2a \d+\.\d+\.\d+/);
    // The telemetry disclosure must NOT pollute the parseable stream.
    expect(stdout).not.toMatch(/Telemetry:/);

    // Disclosure still surfaces — on stderr.
    expect(stderr).toMatch(/Telemetry: on/);
  });

  it('-v behaves identically to --version (stdout, stderr disclosure, exit 0)', () => {
    if (!existsSync(CLI_PATH)) return;
    const long = runVersion('--version');
    const short = runVersion('-v');
    expect(short.status).toBe(0);
    expect(short.stdout.trim()).toBe(long.stdout.trim());
    expect(short.stderr).toMatch(/Telemetry: on/);
  });

  it('OPENA2A_TELEMETRY=off: stdout stays the single version line, no telemetry leak', () => {
    if (!existsSync(CLI_PATH)) return;
    const { stdout, status } = runVersion('--version', 'off');
    expect(status).toBe(0);
    const lines = stdout.trim().split('\n').filter((l) => l.length > 0);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^opena2a \d+\.\d+\.\d+/);
    expect(stdout).not.toMatch(/Telemetry:/);
  });
});
