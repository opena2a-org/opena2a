/**
 * `opena2a "find leaked credentials"` reaches the program as one argument,
 * `find leaked credentials`: the shell has already stripped the quotes, so a
 * check for a leading quote character never fires and Commander reported
 * `unknown command`. One argument containing whitespace is a phrase and goes
 * to the natural-language matcher.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { isPhraseArgument } from '../../src/natural/known-commands.js';
import { classifyInput } from '../../src/router.js';

const INDEX_SRC = resolve(__dirname, '../../src/index.ts');

describe('isPhraseArgument', () => {
  it('accepts a single argument that contains whitespace', () => {
    expect(isPhraseArgument(['find leaked credentials'])).toBe(true);
    expect(isPhraseArgument(['scan for secrets'])).toBe(true);
    expect(isPhraseArgument(['is my agent safe?'])).toBe(true);
    expect(isPhraseArgument(['find\tsecrets'])).toBe(true);
    expect(isPhraseArgument(['  find leaked credentials  '])).toBe(true);
  });

  it('rejects a single word, even padded with spaces', () => {
    expect(isPhraseArgument(['scan'])).toBe(false);
    expect(isPhraseArgument(['  scan  '])).toBe(false);
    expect(isPhraseArgument([''])).toBe(false);
    expect(isPhraseArgument(['   '])).toBe(false);
  });

  it('leaves a flag to Commander', () => {
    expect(isPhraseArgument(['--format json'])).toBe(false);
    expect(isPhraseArgument(['-v x'])).toBe(false);
  });

  it('only applies to exactly one argument', () => {
    expect(isPhraseArgument([])).toBe(false);
    expect(isPhraseArgument(['find leaked', 'credentials'])).toBe(false);
    expect(isPhraseArgument(['scan', 'for secrets'])).toBe(false);
  });
});

describe('classifyInput with a shell-unquoted phrase', () => {
  it('classifies one multi-word argument as natural language', () => {
    expect(classifyInput(['find leaked credentials'])).toEqual({
      type: 'natural',
      value: 'find leaked credentials',
      args: [],
    });
  });

  it('classifies it as natural language even when it starts with a command name', () => {
    expect(classifyInput(['scan for secrets'])).toEqual({
      type: 'natural',
      value: 'scan for secrets',
      args: [],
    });
  });

  it('still classifies a known command with its arguments as a subcommand', () => {
    expect(classifyInput(['scan', 'for', 'secrets']).type).toBe('subcommand');
  });

  it('still treats a single unknown word as a search', () => {
    expect(classifyInput(['quantum']).type).toBe('search');
  });
});

describe('index.ts routes a phrase argument before Commander parses argv', () => {
  it('sends a phrase argument down the classifier path', () => {
    const src = readFileSync(INDEX_SRC, 'utf-8');
    const block = /const isSpecialInput =[\s\S]*?\);/.exec(src);
    expect(block, 'isSpecialInput declaration not found in index.ts').not.toBeNull();
    expect(block![0]).toContain('isPhraseArgument(rawArgs)');
    expect(src.indexOf('const isSpecialInput')).toBeLessThan(src.indexOf('program.parseAsync(process.argv)'));
  });
});
