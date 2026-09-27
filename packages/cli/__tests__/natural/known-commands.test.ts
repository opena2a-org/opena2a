/**
 * #291: the unquoted natural-language fallback must not answer for an
 * explicit command invocation. `opena2a fix-all --with-aim` printed
 * "Matched: opena2a identity" and exited 0; every unregistered verb has to
 * exit non-zero in both its bare and its flag-bearing form.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  knownCommandNames,
  looksLikeCommandInvocation,
  shouldTryNaturalLanguageFallback,
} from '../../src/natural/known-commands.js';

const CLI_PATH = resolve(__dirname, '../../dist/index.js');
const INDEX_SRC = resolve(__dirname, '../../src/index.ts');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

describe('looksLikeCommandInvocation (#291)', () => {
  it('treats a flag after the first token as an invocation', () => {
    expect(looksLikeCommandInvocation(['fix-all', '--with-aim'])).toBe(true);
    expect(looksLikeCommandInvocation(['rollback', '--dry-run'])).toBe(true);
    expect(looksLikeCommandInvocation(['find', 'secrets', '-v'])).toBe(true);
  });

  it('treats a compound (hyphenated) first token as an invocation', () => {
    expect(looksLikeCommandInvocation(['fix-all', '.'])).toBe(true);
    expect(looksLikeCommandInvocation(['harden-souls', 'my', 'agent'])).toBe(true);
  });

  it('leaves ordinary phrases alone', () => {
    expect(looksLikeCommandInvocation(['find', 'leaked', 'credentials'])).toBe(false);
    expect(looksLikeCommandInvocation(['what', 'is', 'shadow', 'ai'])).toBe(false);
    expect(looksLikeCommandInvocation([])).toBe(false);
  });
});

// `fix-all` and `rollback` are registered since #269, so the cases below use
// verbs that are not; each is asserted unregistered so the cases cannot go
// stale the same way.
const UNREGISTERED_INVOCATIONS = [
  ['fix-everything', '--with-aim'],
  ['harden-souls', '.'],
  ['undo', '--dry-run'],
  ['undo', '.', '--ci'],
];

describe('shouldTryNaturalLanguageFallback (#291)', () => {
  it('never tries an unregistered verb in its flag-bearing or bare compound form', () => {
    for (const argv of UNREGISTERED_INVOCATIONS) {
      expect(knownCommandNames(), argv[0]).not.toContain(argv[0]);
      expect(shouldTryNaturalLanguageFallback(argv), argv.join(' ')).toBe(false);
    }
  });

  it('never tries a registered command or a leading flag', () => {
    expect(shouldTryNaturalLanguageFallback(['skill', 'create', 'my-skill'])).toBe(false);
    expect(shouldTryNaturalLanguageFallback(['scan-soul', 'my', 'dir'])).toBe(false);
    expect(shouldTryNaturalLanguageFallback(['--ci', 'scan'])).toBe(false);
  });

  it('still tries an unquoted multi-word phrase', () => {
    expect(shouldTryNaturalLanguageFallback(['find', 'leaked', 'credentials'])).toBe(true);
  });

  it('needs at least two tokens', () => {
    expect(shouldTryNaturalLanguageFallback(['fix'])).toBe(false);
  });
});

describe('known command names match the program (#291 drift guard)', () => {
  it('every command registered in src/index.ts is a known command', () => {
    const src = readFileSync(INDEX_SRC, 'utf-8');
    const registered = [...src.matchAll(/\.command\('([a-z][a-z0-9-]*)/g)].map(m => m[1]);
    expect(registered.length).toBeGreaterThan(20);
    const known = new Set(knownCommandNames());
    expect(registered.filter(name => !known.has(name))).toEqual([]);
  });
});

describe('built CLI rejects unregistered verbs in both forms (#291)', () => {
  function run(args: string[]): { stdout: string; stderr: string; status: number } {
    const xdg = mkdtempSync(join(tmpdir(), 'opena2a-unknown-verb-'));
    try {
      const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
        encoding: 'utf8',
        timeout: 20000,
        cwd: xdg,
        env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', XDG_CONFIG_HOME: xdg },
      });
      return {
        stdout: (res.stdout ?? '').replace(STRIP_ANSI, ''),
        stderr: (res.stderr ?? '').replace(STRIP_ANSI, ''),
        status: res.status ?? 1,
      };
    } finally {
      rmSync(xdg, { recursive: true, force: true });
    }
  }

  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  for (const argv of UNREGISTERED_INVOCATIONS.slice(0, 3)) {
    it(`opena2a ${argv.join(' ')} exits non-zero and names the verb`, () => {
      if (!existsSync(CLI_PATH)) return;
      const { stdout, stderr, status } = run(argv);
      expect(status).not.toBe(0);
      expect(stderr).toContain(`unknown command '${argv[0]}'`);
      expect(stdout).not.toContain('Matched:');
    });
  }
});
