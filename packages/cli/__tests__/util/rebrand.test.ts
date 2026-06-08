/**
 * Rebrand helper tests (issue #190): bundled-tool command citations must be
 * rewritten to their opena2a-prefixed form, and no surfaced next-step command
 * may start with a bundled tool name.
 */
import { describe, it, expect } from 'vitest';
import { rebrandBundledCommands, createLineRebrander } from '../../src/util/rebrand.js';

const BUNDLED_TOOLS = ['hackmyagent', 'ai-trust', 'cryptoserve'];

describe('rebrandBundledCommands', () => {
  it('rewrites hackmyagent secure/scan (bare and npx) to opena2a', () => {
    expect(rebrandBundledCommands('Run `npx hackmyagent secure .`')).toBe('Run `opena2a secure .`');
    expect(rebrandBundledCommands('hackmyagent secure ./agent')).toBe('opena2a secure ./agent');
    expect(rebrandBundledCommands('Submit a scan: hackmyagent scan express')).toBe('Submit a scan: opena2a scan express');
    expect(rebrandBundledCommands('npx hackmyagent scan')).toBe('opena2a scan');
  });

  it('rewrites `ai-trust check <pkg>` to `opena2a registry <pkg>` (faithful mapping)', () => {
    expect(rebrandBundledCommands('ai-trust check express --rescan')).toBe('opena2a registry express --rescan');
    expect(rebrandBundledCommands('npx ai-trust check lodash')).toBe('opena2a registry lodash');
    expect(rebrandBundledCommands('Usage: ai-trust check [options] <name>')).toBe('Usage: opena2a registry [options] <name>');
  });

  it('leaves bundled subcommands with no faithful opena2a equivalent untouched', () => {
    // `ai-trust audit` is not exposed 1:1 by opena2a-cli; rewriting it would
    // suggest a command that does not resolve, which is worse than the original.
    expect(rebrandBundledCommands('ai-trust audit package.json')).toBe('ai-trust audit package.json');
  });

  it('does not over-match a hyphenated subcommand into a broken opena2a command', () => {
    // `ai-trust check-deps` must NOT become `opena2a registry-deps` (nonexistent).
    expect(rebrandBundledCommands('ai-trust check-deps')).toBe('ai-trust check-deps');
    // But the real `check` subcommand still maps.
    expect(rebrandBundledCommands('ai-trust check express')).toBe('opena2a registry express');
  });

  it('rewrites npx cryptoserve to opena2a crypto', () => {
    expect(rebrandBundledCommands('npx cryptoserve scan')).toBe('opena2a crypto scan');
  });

  it('is a no-op on text with no bundled-tool citations', () => {
    const s = 'Run `opena2a check express` for a local scan.';
    expect(rebrandBundledCommands(s)).toBe(s);
  });

  it('regression: faithfully-mapped next-steps no longer start with a bundled tool name', () => {
    const surfaced = [
      'npx hackmyagent secure',
      'hackmyagent scan . --publish',
      'ai-trust check express --rescan',
      'npx cryptoserve scan',
    ].map(rebrandBundledCommands);
    for (const cmd of surfaced) {
      for (const tool of BUNDLED_TOOLS) {
        expect(cmd.startsWith(tool)).toBe(false);
        expect(cmd.startsWith(`npx ${tool}`)).toBe(false);
      }
    }
  });
});

describe('createLineRebrander (streaming, line-buffered)', () => {
  it('rebrands complete lines and buffers a trailing partial line until flush', () => {
    const r = createLineRebrander();
    // First chunk ends mid-line: only the complete line is emitted, rebranded.
    const out1 = r.push('Next steps:\nRun `ai-trust check exp');
    expect(out1).toBe('Next steps:\n');
    // Second chunk completes the line.
    const out2 = r.push('ress --rescan`\n');
    expect(out2).toBe('Run `opena2a registry express --rescan`\n');
    expect(r.flush()).toBe('');
  });

  it('rebrands a token even when split across a chunk boundary', () => {
    const r = createLineRebrander();
    expect(r.push('hackmyagent sec')).toBe('');
    expect(r.push('ure .\n')).toBe('opena2a secure .\n');
  });

  it('streams carriage-return progress frames live (does not withhold until flush)', () => {
    const r = createLineRebrander();
    // A spinner that rewrites one line with \r and no newline must stream now.
    expect(r.push('Scanning... |\r')).toBe('Scanning... |\r');
    expect(r.push('Scanning... /\r')).toBe('Scanning... /\r');
    expect(r.flush()).toBe('');
  });

  it('flush emits a trailing line with no newline', () => {
    const r = createLineRebrander();
    expect(r.push('tail without newline: npx ai-trust check x')).toBe('');
    expect(r.flush()).toBe('tail without newline: opena2a registry x');
  });
});

// issue #191: import-adapter (secretless-ai) + python-adapter (cryptoserve)
// help/usage surfaces, plus the adversarial non-citation cases that a bare
// program-name rule would corrupt.
describe('rebrandBundledCommands — #191 import/python surfaces', () => {
  describe('secretless-ai (all verbs -> opena2a secrets)', () => {
    it('rewrites verbs (bare and npx) to opena2a secrets <verb>', () => {
      expect(rebrandBundledCommands('npx secretless-ai scan')).toBe('opena2a secrets scan');
      expect(rebrandBundledCommands('secretless-ai init')).toBe('opena2a secrets init');
      expect(rebrandBundledCommands('secretless-ai verify --all')).toBe('opena2a secrets verify --all');
    });

    it('keeps hyphenated subcommands intact (longest-first)', () => {
      expect(rebrandBundledCommands('secretless-ai scan-history')).toBe('opena2a secrets scan-history');
      expect(rebrandBundledCommands('secretless-ai clean-history')).toBe('opena2a secrets clean-history');
    });
  });

  describe('cryptoserve (all verbs -> opena2a crypto)', () => {
    it('rewrites verbs (bare and npx) to opena2a crypto <verb>', () => {
      expect(rebrandBundledCommands('cryptoserve login')).toBe('opena2a crypto login');
      expect(rebrandBundledCommands('cryptoserve scan . --push')).toBe('opena2a crypto scan . --push');
      expect(rebrandBundledCommands('cryptoserve hash-password')).toBe('opena2a crypto hash-password');
    });

    it('rewrites the bare-program Usage line (placeholder, not a real verb)', () => {
      expect(rebrandBundledCommands('  Usage: cryptoserve <command> [options]'))
        .toBe('  Usage: opena2a crypto <command> [options]');
    });
  });

  describe('hackmyagent check verb (added in #191)', () => {
    it('rewrites check to opena2a check', () => {
      expect(rebrandBundledCommands('$ hackmyagent check <package>')).toBe('$ opena2a check <package>');
    });
  });

  describe('ADVERSARIAL — must NOT corrupt non-citation tool mentions', () => {
    it('preserves a Python import statement (verbatim from cryptoserve help)', () => {
      // `import` is not a cryptoserve CLI verb, so `cryptoserve import` never matches.
      const code = 'from cryptoserve import CryptoServe';
      expect(rebrandBundledCommands(code)).toBe(code);
    });

    it('preserves a class constructor reference', () => {
      const code = 'crypto = CryptoServe(app_name="my-app")';
      expect(rebrandBundledCommands(code)).toBe(code);
    });

    it('preserves package-install lines', () => {
      expect(rebrandBundledCommands('npm install secretless-ai')).toBe('npm install secretless-ai');
      expect(rebrandBundledCommands('pip install cryptoserve')).toBe('pip install cryptoserve');
      expect(rebrandBundledCommands('npm i -g hackmyagent')).toBe('npm i -g hackmyagent');
    });

    it('preserves JS module specifiers (a quote, not a verb, follows the name)', () => {
      const code = "import { AttackScanner } from 'hackmyagent';";
      expect(rebrandBundledCommands(code)).toBe(code);
      const code2 = "const sl = require('secretless-ai');";
      expect(rebrandBundledCommands(code2)).toBe(code2);
    });

    it('preserves bare program mentions with no following verb', () => {
      expect(rebrandBundledCommands('Powered by cryptoserve.')).toBe('Powered by cryptoserve.');
      expect(rebrandBundledCommands('See the secretless-ai docs')).toBe('See the secretless-ai docs');
    });

    it('does NOT rewrite a tool token embedded in a larger token (left anchor)', () => {
      // `\b` would match inside these at the `-`/`/` boundary; the lookbehind
      // requires a true token start, so a scoped/forked name or path survives.
      expect(rebrandBundledCommands('my-secretless-ai scan')).toBe('my-secretless-ai scan');
      expect(rebrandBundledCommands('@myorg/secretless-ai scan')).toBe('@myorg/secretless-ai scan');
      expect(rebrandBundledCommands('tools/cryptoserve scan')).toBe('tools/cryptoserve scan');
      expect(rebrandBundledCommands('my-ai-trust check x')).toBe('my-ai-trust check x');
    });

    it('does NOT half-rewrite a real-but-unmapped hyphenated subcommand (right anchor)', () => {
      // `hackmyagent check-metadata` is a real HMA verb opena2a does not expose;
      // it must stay intact, not become the nonexistent `opena2a check-metadata`.
      expect(rebrandBundledCommands('hackmyagent check-metadata')).toBe('hackmyagent check-metadata');
      expect(rebrandBundledCommands('hackmyagent scan-soul')).toBe('hackmyagent scan-soul');
    });
  });
});
