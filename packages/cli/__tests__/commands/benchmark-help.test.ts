/**
 * `opena2a benchmark --help` names the global options the command reads.
 *
 * The handler takes --ci, --format and --verbose from the root program, so
 * its own Options list never showed them: a reader of `benchmark --help` had
 * no way to learn that --verbose prints the per-category breakdown or that
 * --format json switches the output, nor where on the command line they go.
 * The help now names each of them after the exit codes and shows them
 * written before the subcommand.
 *
 * Runs `benchmark --help` from the build, and the example placement on an
 * empty directory to show it is accepted there.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const CLI_PATH = resolve(__dirname, '../../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

let base: string;

beforeAll(() => {
  base = mkdtempSync(join(tmpdir(), 'opena2a-benchmark-help-'));
});

afterAll(() => {
  rmSync(base, { recursive: true, force: true });
});

function runCli(args: string[]): { stdout: string; status: number | null } {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf8',
    timeout: 60_000,
    input: '',
    cwd: base,
    env: {
      ...process.env,
      NODE_OPTIONS: '',
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: base,
      XDG_CONFIG_HOME: join(base, '.config'),
    },
  });
  return { stdout: (res.stdout ?? '').replace(STRIP_ANSI, ''), status: res.status };
}

describe('benchmark --help', () => {
  it('names --ci, --format <type> and --verbose as options written before the subcommand', () => {
    const { stdout, status } = runCli(['benchmark', '--help']);
    expect(status).toBe(0);
    const lines = stdout.split('\n');
    for (const flag of ['--ci', '--format <type>', '--verbose']) {
      expect(lines.some((l) => l.startsWith(`  ${flag}  `)), `no row for ${flag}`).toBe(true);
    }
    expect(stdout).toMatch(/before the subcommand/);
    expect(lines).toContain('  opena2a --format json benchmark ./my-agent');
  });

  it('the global options follow the exit codes and the Automation block', () => {
    const { stdout } = runCli(['benchmark', '--help']);
    const exitCodes = stdout.indexOf('Exit codes:');
    const automation = stdout.indexOf('Automation:');
    const globals = stdout.indexOf('Global options benchmark reads');
    expect(exitCodes).toBeGreaterThan(-1);
    expect(automation).toBeGreaterThan(exitCodes);
    expect(globals).toBeGreaterThan(automation);
  });

  it('accepts --format json before the subcommand, as the example writes it', () => {
    const target = mkdtempSync(join(base, 'project-'));
    const { stdout, status } = runCli(['--format', 'json', 'benchmark', target]);
    expect(status).toBe(0);
    const doc = JSON.parse(stdout.slice(stdout.indexOf('{'), stdout.lastIndexOf('}') + 1));
    expect(doc.benchmark).toMatch(/^OASB-1/);
  });
});
