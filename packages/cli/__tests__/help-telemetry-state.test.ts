/**
 * `opena2a --help` states the effective telemetry state (#388).
 *
 * The epilogue was a fixed line, so with OPENA2A_TELEMETRY=off the help read
 * "Usage telemetry is on" while `opena2a --version` in the same environment
 * printed "Telemetry: off".
 *
 * The end-to-end cases exercise the built `dist/index.js` with telemetry off
 * only, so no run sends an event.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';

import { telemetryHelpLine } from '../src/util/telemetry-help.js';

const CLI_PATH = resolve(__dirname, '../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

describe('telemetryHelpLine', () => {
  it('says on, with the persistent install ID and the opt-out, when telemetry is on', () => {
    expect(telemetryHelpLine({ enabled: true })).toBe(
      'Usage telemetry is on and each event carries a persistent install ID. Disable: OPENA2A_TELEMETRY=off',
    );
  });

  it('says off after a saved opt-out', () => {
    expect(telemetryHelpLine({ enabled: false })).toBe(
      'Usage telemetry is off: no events are sent and no install ID is kept. Details: opena2a telemetry status',
    );
  });

  it('names the environment setting that turned it off', () => {
    expect(telemetryHelpLine({ enabled: false, suppressedBy: 'env-opt-out' })).toContain(
      'Usage telemetry is off (OPENA2A_TELEMETRY=off is set):',
    );
    expect(telemetryHelpLine({ enabled: false, suppressedBy: 'do-not-track' })).toContain(
      'Usage telemetry is off (DO_NOT_TRACK is set):',
    );
    expect(telemetryHelpLine({ enabled: false, suppressedBy: 'ci' })).toContain(
      'Usage telemetry is off (CI environment detected):',
    );
    expect(telemetryHelpLine({ enabled: false, suppressedBy: 'test-runner' })).toContain(
      'Usage telemetry is off (test runner detected):',
    );
    expect(telemetryHelpLine({ enabled: false, suppressedBy: 'ephemeral-home' })).toContain(
      'Usage telemetry is off (temporary home directory detected):',
    );
  });
});

describe('opena2a --help telemetry line', () => {
  // A fresh config directory, so no saved preference from the host applies.
  let xdgConfigHome: string;

  beforeAll(() => {
    xdgConfigHome = mkdtempSync(join(tmpdir(), 'opena2a-help-telemetry-'));
  });

  afterAll(() => {
    rmSync(xdgConfigHome, { recursive: true, force: true });
  });

  function runHelp(env: Record<string, string>): { stdout: string; status: number } {
    const childEnv: NodeJS.ProcessEnv = {
      ...process.env,
      NODE_OPTIONS: '',
      NO_COLOR: '1',
      XDG_CONFIG_HOME: xdgConfigHome,
    };
    delete childEnv.OPENA2A_TELEMETRY;
    delete childEnv.DO_NOT_TRACK;
    const res = spawnSync(process.execPath, [CLI_PATH, '--help'], {
      encoding: 'utf8',
      timeout: 20000,
      env: { ...childEnv, ...env },
    });
    return { stdout: (res.stdout ?? '').replace(STRIP_ANSI, ''), status: res.status ?? 1 };
  }

  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  it('says off with OPENA2A_TELEMETRY=off, as --version does', () => {
    const { stdout, status } = runHelp({ OPENA2A_TELEMETRY: 'off' });
    expect(status).toBe(0);
    expect(stdout).toContain('Usage telemetry is off (OPENA2A_TELEMETRY=off is set):');
    expect(stdout).not.toContain('Usage telemetry is on');
  });

  it('says off with DO_NOT_TRACK=1', () => {
    const { stdout, status } = runHelp({ DO_NOT_TRACK: '1' });
    expect(status).toBe(0);
    expect(stdout).toContain('Usage telemetry is off (DO_NOT_TRACK is set):');
    expect(stdout).not.toContain('Usage telemetry is on');
  });
});
