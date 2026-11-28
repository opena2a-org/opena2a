/**
 * The next step `detect --registry`, `mcp audit`, `mcp verify` and `verify`
 * print under a Blocked or Warning trust answer is a command each one's own
 * --help names, and the help says how a level is shown.
 *
 * The help is read from the built `dist/index.js`, as in help-layout.test.ts.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { trustNextStep } from '../../src/util/trust-answer.js';

const CLI_PATH = resolve(__dirname, '../../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

function help(args: string[]): string {
  const home = mkdtempSync(join(tmpdir(), 'opena2a-trust-help-'));
  try {
    const res = spawnSync(process.execPath, [CLI_PATH, ...args, '--help'], {
      encoding: 'utf8',
      timeout: 20000,
      input: '',
      env: {
        ...process.env,
        HOME: home,
        XDG_CONFIG_HOME: join(home, '.config'),
        NODE_OPTIONS: '',
        NO_COLOR: '1',
        OPENA2A_TELEMETRY: 'off',
      },
    });
    expect(res.status).toBe(0);
    return (res.stdout ?? '').replace(STRIP_ANSI, '').replace(/\s+/g, ' ');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

/** The printed next step with its package operand written as the help writes it. */
const NEXT_STEP = trustNextStep('pkg').replace(/ pkg$/, ' <package>');

describe('the trust next step is named in each command\'s --help', () => {
  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  for (const args of [['detect'], ['mcp', 'audit'], ['mcp', 'verify'], ['verify']]) {
    it.runIf(existsSync(CLI_PATH))(`${args.join(' ')} --help names ${NEXT_STEP} and the level words`, () => {
      const text = help(args);
      expect(NEXT_STEP).toBe('opena2a check <package>');
      expect(text).toContain(NEXT_STEP);
      expect(text).toContain('A Blocked or Warning answer is followed by its next step');
      expect(text).toContain('Blocked, Warning, Listed, Scanned, Verified; level 0 to 4');
    });
  }

  it.runIf(existsSync(CLI_PATH))('the root --help lists check, the command the next step runs', () => {
    expect(help([])).toMatch(/\bcheck\b/);
  });
});
