/**
 * #422: a mistyped subcommand of guard, shield or runtime gets one answer,
 * with or without --help. `opena2a guard signs --help` named the word as an
 * unknown guard subcommand and printed the parent help, while
 * `opena2a guard signs` printed a different first line and a hand-written
 * subcommand list. Both now print the same stderr and exit 1.
 *
 * Exercises the built `dist/index.js` end-to-end, each run in its own
 * scratch HOME and XDG_CONFIG_HOME so no first-run notice tells them apart.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';

const CLI_PATH = resolve(__dirname, '../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

function run(args: string[]): { stdout: string; stderr: string; status: number | null } {
  const home = mkdtempSync(join(tmpdir(), 'opena2a-unknown-sub-'));
  try {
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
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

describe('an unknown subcommand prints the same message with or without --help (#422)', () => {
  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  for (const [parent, word] of [
    ['guard', 'signs'],
    ['shield', 'stats'],
    ['runtime', 'stat'],
  ]) {
    it(`${parent} ${word}`, () => {
      const plain = run([parent, word]);
      const help = run([parent, word, '--help']);

      expect(plain.stderr.startsWith(`Unknown ${parent} subcommand: ${word}\n\n`)).toBe(true);
      expect(plain.stderr).toContain(`Usage: opena2a ${parent}`);
      expect(plain.status).toBe(1);
      expect(plain.stdout).toBe('');

      expect(help.stderr).toBe(plain.stderr);
      expect(help.stdout).toBe(plain.stdout);
      expect(help.status).toBe(plain.status);
    });
  }

  it('a guard directory in the subcommand position is not an unknown subcommand', () => {
    const { stderr } = run(['guard', './missing-dir']);
    expect(stderr).not.toContain('Unknown guard subcommand');
  });
});
