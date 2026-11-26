/**
 * `harden-soul` output is judged safe by both analyzers (#251).
 *
 * `scan-soul` rated the SOUL.md that `harden-soul` writes as hardened while
 * `scan` labelled the same file `soul · malicious`: following the CLI's own
 * advice made the other analyzer call the project unsafe. This runs the built
 * CLI end to end -- `harden-soul` on an empty project, then `scan-soul` and
 * `scan` on the result -- and asserts that neither one objects to the file.
 *
 * The hackmyagent engine runs for real. The environment is built from
 * scratch in a throwaway HOME, and any request leaves through a proxy on a
 * closed port, so the model download `scan` attempts fails at once and the
 * run stays offline.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

const CLI_PATH = resolve(__dirname, '../../dist/index.js');
const RUN_TIMEOUT = 110_000;
/** `scan` takes seconds on its own; the config's 10 s default is too close on a loaded runner. */
const TEST_TIMEOUT = RUN_TIMEOUT + 10_000;
/** A local port nothing listens on: a request to it is refused at once. */
const CLOSED = 'http://127.0.0.1:9';
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

let base: string;
let home: string;
let project: string;
let env: NodeJS.ProcessEnv;

function cli(...args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: project,
    env,
    encoding: 'utf-8',
    timeout: RUN_TIMEOUT,
    maxBuffer: 64 * 1024 * 1024,
  });
  return {
    status: r.status,
    stdout: (r.stdout ?? '').replace(STRIP_ANSI, ''),
    stderr: (r.stderr ?? '').replace(STRIP_ANSI, ''),
  };
}

beforeAll(() => {
  base = mkdtempSync(join(tmpdir(), 'harden-soul-analyzers-'));
  home = join(base, 'home');
  project = join(base, 'project');
  mkdirSync(join(home, '.opena2a'), { recursive: true });
  mkdirSync(project, { recursive: true });
  env = {
    PATH: [dirname(process.execPath), '/usr/bin', '/bin', '/usr/sbin', '/sbin'].join(':'),
    HOME: home,
    TMPDIR: base,
    NODE_OPTIONS: '',
    NO_COLOR: '1',
    OPENA2A_TELEMETRY: 'off',
    XDG_CONFIG_HOME: join(home, '.config'),
    HTTPS_PROXY: CLOSED,
    HTTP_PROXY: CLOSED,
    NO_PROXY: '127.0.0.1,localhost,::1',
    NODE_USE_ENV_PROXY: '1',
  };
});

afterAll(() => {
  if (base) rmSync(base, { recursive: true, force: true });
});

describe('harden-soul then scan and scan-soul (#251)', () => {
  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH), 'run `npm run build` in packages/cli first').toBe(true);
  });

  it('harden-soul writes SOUL.md into the empty project', { timeout: TEST_TIMEOUT }, () => {
    const r = cli('harden-soul', project);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('Governance written to: SOUL.md');
    const soul = readFileSync(join(project, 'SOUL.md'), 'utf-8');
    // The line that once tripped the analyzers: governance that NAMES the
    // attack phrases it refuses. If harden-soul stops writing it, this test
    // no longer exercises #251 and needs a new fixture.
    expect(soul.toLowerCase()).toContain('ignore previous instructions');
  });

  it('scan-soul judges the hardened file safe', { timeout: TEST_TIMEOUT }, () => {
    const r = cli('scan-soul', project, '--format', 'json');
    expect(r.status, r.stderr).toBe(0);
    const result = JSON.parse(r.stdout);
    expect(result.file).toBe('SOUL.md');
    expect(result.level).toBe('hardened');
    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(result.criticalMissing ?? []).toEqual([]);
  });

  it('scan reports no finding against the hardened file', { timeout: TEST_TIMEOUT }, () => {
    const r = cli('scan', project, '--format', 'json');
    expect(r.status, r.stderr).toBe(0);
    const report = JSON.parse(r.stdout);
    const failed: Array<{ checkId: string; severity: string; file?: string }> =
      (report.findings ?? []).filter((f: { passed?: boolean }) => f.passed === false);
    // An injected SOUL.md fails CONFIG-002 (high) and AST-EXFIL-001 here.
    expect(failed.filter((f) => /soul\.md$/i.test(f.file ?? '')).map((f) => f.checkId)).toEqual([]);
    expect(failed.filter((f) => f.severity === 'critical' || f.severity === 'high').map((f) => f.checkId)).toEqual([]);
  });

  it('scan does not label the hardened file malicious, and does not call the project unsafe', { timeout: TEST_TIMEOUT }, () => {
    const r = cli('scan', project);
    expect(r.status, r.stderr).toBe(0);
    const artifact = r.stdout.match(/SOUL\.md\s+soul\s+·\s+([\w-]+)/i);
    expect(artifact, r.stdout).not.toBeNull();
    expect(artifact![1].toLowerCase()).not.toBe('malicious');
    expect(r.stdout).not.toMatch(/Not safe as-is/);
  });

  it('the scans above ran offline: no classifier model reached the scratch HOME', () => {
    // The proxy only binds where Node honours NODE_USE_ENV_PROXY (22.21+, 24+).
    // Elsewhere the model download would succeed and the verdicts above would
    // come from a different analyzer than the one this test pins.
    expect(
      existsSync(join(home, '.nanomind', 'models', 'nanomind-tme.onnx')),
      `scan downloaded its model under ${process.version}; run this test on Node 22.21+ or 24+`,
    ).toBe(false);
  });
});
