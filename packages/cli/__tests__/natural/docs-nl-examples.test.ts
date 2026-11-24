import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { matchIntent } from '../../src/natural/intent-map.js';
import { shouldTryNaturalLanguageFallback } from '../../src/natural/known-commands.js';

/**
 * The natural-language example in the READMEs and the developer guide must
 * run as printed (#480). The docs showed `opena2a "find leaked credentials"`:
 * the shell strips the quotes and hands the CLI one argument holding the whole
 * phrase, which the unquoted fallback does not take (it needs two or more
 * tokens), so Commander answered `unknown command 'find leaked credentials'`
 * and exited 1. The example is now written unquoted, and each word reaches the
 * CLI as its own argument, the way the fallback in src/index.ts reads it.
 */
const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const DOCS = ['README.md', 'docs/use-cases/developer.md', 'packages/cli/README.md'];

function naturalLanguageExamples(file: string): string[] {
  const text = fs.readFileSync(path.join(REPO_ROOT, file), 'utf8');
  return text
    .split('\n')
    .filter(line => /^opena2a\s/.test(line) && /#\s*natural language/i.test(line))
    .map(line => line.replace(/^opena2a\s+/, '').replace(/\s*#.*$/, ''));
}

describe('documented natural-language examples', () => {
  for (const file of DOCS) {
    const examples = naturalLanguageExamples(file);

    it(`${file} shows one natural-language example`, () => {
      expect(examples).toHaveLength(1);
    });

    for (const phrase of examples) {
      it(`${file}: "${phrase}" is unquoted and reaches the natural-language fallback`, () => {
        expect(phrase).not.toMatch(/^["']/);
        expect(shouldTryNaturalLanguageFallback(phrase.split(/\s+/))).toBe(true);
      });

      it(`${file}: "${phrase}" resolves to the read-only credential scan`, () => {
        expect(matchIntent(phrase)?.command).toBe('opena2a secrets scan');
      });
    }
  }

  it('a quoted phrase arrives as one argument, which the fallback does not take', () => {
    expect(shouldTryNaturalLanguageFallback(['find leaked credentials'])).toBe(false);
  });
});
