/**
 * Statements about network use and file writes match what the CLI does.
 *
 * `opena2a --help` printed "Usage telemetry is on" as a fixed string, so it
 * said "on" with OPENA2A_TELEMETRY=off set. The security-team guide said
 * `detect` "does not modify any files" while it creates
 * ~/.opena2a/config.json, and that `--registry` was the only flag that leaves
 * the machine while usage telemetry, on by default, sends an event for each
 * command. The help now prints the live telemetry state and the guide states
 * both behaviours.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { telemetryHelpLine } from '../src/util/telemetry-help.js';

const CLI_PATH = resolve(__dirname, '../dist/index.js');
const GUIDE_PATH = resolve(__dirname, '../../../docs/use-cases/security-team.md');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

let sandbox: string;

beforeEach(() => {
  sandbox = mkdtempSync(join(tmpdir(), 'opena2a-help-tele-'));
});

afterEach(() => {
  rmSync(sandbox, { recursive: true, force: true });
});

/**
 * Run the built CLI with a fresh HOME and XDG_CONFIG_HOME so neither the
 * host's saved telemetry preference nor its ~/.opena2a is read or written.
 */
function runCli(args: string[], telemetry: string): { stdout: string; status: number } {
  const home = join(sandbox, 'home');
  mkdirSync(home, { recursive: true });
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    XDG_CONFIG_HOME: join(sandbox, 'xdg'),
    NODE_OPTIONS: '',
    NO_COLOR: '1',
    OPENA2A_TELEMETRY: telemetry,
  };
  delete env.DO_NOT_TRACK;
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf8',
    timeout: 60000,
    env,
  });
  return { stdout: (res.stdout ?? '').replace(STRIP_ANSI, ''), status: res.status ?? 1 };
}

function telemetryBlock(help: string): string {
  const start = help.indexOf('\nTelemetry:\n');
  expect(start).toBeGreaterThan(-1);
  return help.slice(start, help.indexOf('\nLearn more:', start));
}

describe('telemetryHelpLine', () => {
  it('says on, with the persistent install ID and the opt-out, while telemetry is on', () => {
    const line = telemetryHelpLine({ enabled: true });
    expect(line).toContain('Usage telemetry is on');
    expect(line).toContain('persistent install ID');
    expect(line).toContain('Disable: OPENA2A_TELEMETRY=off');
  });

  it.each([
    ['env-opt-out', 'OPENA2A_TELEMETRY=off is set'],
    ['do-not-track', 'DO_NOT_TRACK is set'],
    ['ci', 'CI environment detected'],
    ['test-runner', 'test runner detected'],
    ['ephemeral-home', 'temporary home directory detected'],
  ] as const)('names the reason when it is off because of %s', (suppressedBy, reason) => {
    const line = telemetryHelpLine({ enabled: false, suppressedBy });
    expect(line).toContain(`Usage telemetry is off (${reason}): no events are sent`);
    expect(line).not.toContain('is on');
  });

  it('says off, with no environment reason, after a saved opt-out', () => {
    const line = telemetryHelpLine({ enabled: false });
    expect(line).toContain('Usage telemetry is off: no events are sent');
    expect(line).not.toContain('is on');
  });
});

describe('opena2a --help telemetry block (built CLI)', () => {
  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  it('says telemetry is off when OPENA2A_TELEMETRY=off is set', () => {
    if (!existsSync(CLI_PATH)) return;
    const { stdout, status } = runCli(['--help'], 'off');
    expect(status).toBe(0);
    const block = telemetryBlock(stdout);
    expect(block).toContain('Usage telemetry is off (OPENA2A_TELEMETRY=off is set):');
    expect(block).not.toContain('Usage telemetry is on');
  });

  it('says telemetry is off when a saved preference turned it off', () => {
    if (!existsSync(CLI_PATH)) return;
    mkdirSync(join(sandbox, 'xdg', 'opena2a'), { recursive: true });
    writeFileSync(join(sandbox, 'xdg', 'opena2a', 'telemetry.json'), '{"enabled":false}\n');
    const { stdout, status } = runCli(['--help'], 'on');
    expect(status).toBe(0);
    const block = telemetryBlock(stdout);
    expect(block).toContain('Usage telemetry is off: no events are sent');
    expect(block).not.toContain('Usage telemetry is on');
  });

  it('says telemetry is off, and why, when the environment suppresses it', () => {
    if (!existsSync(CLI_PATH)) return;
    // No opt-in or opt-out: the CLI runs under this test runner with a HOME
    // inside the temporary directory, so telemetry is suppressed (as CI when
    // the suite runs in CI).
    const { stdout, status } = runCli(['--help'], '');
    expect(status).toBe(0);
    const block = telemetryBlock(stdout);
    expect(block).toMatch(
      /Usage telemetry is off \((CI environment detected|test runner detected)\):/,
    );
    expect(block).not.toContain('Usage telemetry is on');
  });

  it('says telemetry is on when it is on', () => {
    if (!existsSync(CLI_PATH)) return;
    const { stdout, status } = runCli(['--help'], 'on');
    expect(status).toBe(0);
    const block = telemetryBlock(stdout);
    expect(block).toContain('Usage telemetry is on and each event carries a persistent install ID.');
  });
});

describe('security-team guide states what detect writes and sends', () => {
  it('detect creates ~/.opena2a/config.json, and the guide says so', () => {
    if (!existsSync(CLI_PATH)) return;
    const project = join(sandbox, 'project');
    mkdirSync(project, { recursive: true });
    runCli(['detect', project], 'off');
    expect(existsSync(join(sandbox, 'home', '.opena2a', 'config.json'))).toBe(true);

    const guide = readFileSync(GUIDE_PATH, 'utf8');
    expect(guide).not.toContain('does not modify any files');
    expect(guide).toContain('`~/.opena2a/config.json`');
  });

  it('the guide does not name --registry as the only network use', () => {
    const guide = readFileSync(GUIDE_PATH, 'utf8');
    expect(guide).not.toContain('`--registry` is the only flag on this page that leaves the machine');
    expect(guide).toContain('usage telemetry is on by default and sends one event for each command run');
  });
});
