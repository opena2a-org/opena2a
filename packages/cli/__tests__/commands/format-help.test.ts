/**
 * `--format` help names what each command produces (#412).
 *
 * The global option read "Output format: text, json, sarif" for every
 * command, while `review` and `detect` refuse `sarif` with exit 2, and their
 * own `--help` named no format at all. Each now lists the formats it
 * accepts, and the list is checked against the one the command enforces.
 * Exercises the built `dist/index.js`, because help is assembled by the
 * command-line parser.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { DETECT_FORMATS } from '../../src/commands/detect.js';
import { REVIEW_FORMATS } from '../../src/commands/review.js';

const CLI_PATH = resolve(__dirname, '../../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

let root: string;
let env: NodeJS.ProcessEnv;

function help(args: string[]): string {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args, '--help'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 60_000,
    env,
  });
  expect(res.status).toBe(0);
  return (res.stdout ?? '').replace(STRIP_ANSI, '');
}

/** The formats a command's help lists, one `--format <name>` row each. */
function listedFormats(text: string): string[] {
  return [...text.matchAll(/^ {2}--format (\S+) /gm)].map(m => m[1]);
}

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'opena2a-format-help-'));
  const home = join(root, 'home');
  mkdirSync(home);
  env = {
    PATH: process.env.PATH,
    HOME: home,
    XDG_CONFIG_HOME: join(home, '.config'),
  };
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('--format help (#412)', () => {
  it.each([
    ['review', REVIEW_FORMATS],
    ['detect', DETECT_FORMATS],
  ] as const)('%s --help lists exactly the formats it accepts', (command, formats) => {
    const text = help([command]);
    expect(listedFormats(text)).toEqual([...formats]);
    expect(text).toContain('Any other --format value, sarif included, exits 2.');
  });

  it('the global --format help does not offer sarif to every command', () => {
    const line = help([]).split('\n').find(l => l.trimStart().startsWith('--format <type>'));
    expect(line).toBeDefined();
    expect(line).toMatch(/sarif where a command produces it/);
  });
});
