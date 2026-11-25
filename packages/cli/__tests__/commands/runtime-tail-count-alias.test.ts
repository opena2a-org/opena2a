/**
 * `opena2a runtime tail -c 5` failed with "too many arguments for 'runtime'":
 * the runtime command declared only `--count`. `-c` is now its short form and
 * returns the same events as `--count 5`.
 *
 * Exercises the built `dist/index.js` end-to-end, in a scratch HOME whose
 * project holds an ARP event log of eight events.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';

const CLI_PATH = resolve(__dirname, '../../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

let home: string;

beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), 'opena2a-runtime-tail-c-'));
  const arpDir = join(home, '.opena2a', 'arp');
  mkdirSync(arpDir, { recursive: true });
  const events = Array.from({ length: 8 }, (_, i) =>
    JSON.stringify({ timestamp: `2026-01-01T00:00:0${i}Z`, severity: 'info', message: `event ${i}` }),
  );
  writeFileSync(join(arpDir, 'events.jsonl'), events.join('\n') + '\n');
});

afterAll(() => {
  rmSync(home, { recursive: true, force: true });
});

function run(args: string[]): { stdout: string; stderr: string; status: number | null } {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: home,
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...process.env,
      NODE_OPTIONS: '',
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
      XDG_CONFIG_HOME: join(home, '.config'),
    },
  });
  return {
    stdout: (res.stdout ?? '').replace(STRIP_ANSI, ''),
    stderr: (res.stderr ?? '').replace(STRIP_ANSI, ''),
    status: res.status,
  };
}

describe('runtime tail -c is the short form of --count', () => {
  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  it('runtime tail -c 5 returns the last five events, as --count 5 does', () => {
    const short = run(['runtime', 'tail', '-c', '5', '--format', 'json']);
    const long = run(['runtime', 'tail', '--count', '5', '--format', 'json']);

    expect(short.stderr).not.toContain('too many arguments');
    expect(short.status).toBe(0);
    const parsed = JSON.parse(short.stdout);
    expect(parsed.total).toBe(8);
    expect(parsed.events.map((e: { message: string }) => e.message)).toEqual([
      'event 3', 'event 4', 'event 5', 'event 6', 'event 7',
    ]);

    expect(long.status).toBe(0);
    expect(short.stdout).toBe(long.stdout);
  });

  it('runtime tail -c 5 prints the last five events as text', () => {
    const res = run(['runtime', 'tail', '-c', '5']);

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('Last 5 events (8 total)');
    expect(res.stdout).toContain('event 7');
    expect(res.stdout).not.toContain('event 2');
  });
});
