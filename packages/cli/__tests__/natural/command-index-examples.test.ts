/**
 * `opena2a ~credentials` lists `opena2a secrets scan` with the
 * example `find leaked API keys`, but that phrase matched no intent and
 * `opena2a find leaked API keys` failed with `unknown command 'find'`.
 *
 * Every example the semantic index prints must resolve through the
 * natural-language matcher to the command the index lists it under (or a
 * subcommand of it: `opena2a runtime` -> `opena2a runtime start`).
 * help-nl-examples.test.ts covers the `--help` examples; this covers the
 * index. When this fails, fix the matcher, not the example.
 *
 * The index prints an example for the user to type after `opena2a`. Typed
 * unquoted, it reaches the matcher only through the fallback in index.ts,
 * which skips a single word and any phrase whose first word is a registered
 * command: `opena2a scan for hardcoded secrets` ran `scan` on a directory
 * named `for`, and `opena2a detect credentials` ran `detect` on one named
 * `credentials`. So each example must pass that fallback as typed, and must
 * hold nothing the shell would read (`what's the status` left a quote open).
 * When one of these fails, reword the example.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { matchIntent } from '../../src/natural/intent-map.js';
import { isKnownCommand, shouldTryNaturalLanguageFallback } from '../../src/natural/known-commands.js';

interface IndexEntry {
  id: string;
  path: string;
  examples?: string[];
}

const INDEX_PATH = resolve(__dirname, '../../src/semantic/command-index.json');
const entries = JSON.parse(readFileSync(INDEX_PATH, 'utf-8')) as IndexEntry[];

// An example may sit under more than one entry ("security audit" is under
// both `opena2a scan` and `opena2a init`); it has to resolve to one of them.
const pathsByExample = new Map<string, string[]>();
for (const entry of entries) {
  for (const example of entry.examples ?? []) {
    pathsByExample.set(example, [...(pathsByExample.get(example) ?? []), entry.path]);
  }
}

// Characters a POSIX shell treats specially in an unquoted word.
const SHELL_SPECIAL = /['"`$\\;&|<>(){}[\]*?!#~]/;

function isUnder(command: string, path: string): boolean {
  return command === path || command.startsWith(`${path} `);
}

describe('semantic index examples resolve through the matcher', () => {
  it('the index lists examples to check', () => {
    expect(entries.length).toBeGreaterThan(0);
    expect(pathsByExample.size).toBeGreaterThan(0);
  });

  for (const [example, paths] of pathsByExample) {
    it(`"${example}" resolves under ${paths.join(' or ')}`, () => {
      const command = matchIntent(example)?.command;
      expect(command, `"${example}" matched no intent`).toBeDefined();
      expect(paths.some(p => isUnder(command as string, p)), `"${example}" -> ${command}`).toBe(true);
    });
  }
});

describe('semantic index examples reach the matcher when typed as shown', () => {
  for (const example of pathsByExample.keys()) {
    const tokens = example.split(/\s+/);

    it(`"${example}" first word "${tokens[0]}" is not a registered command`, () => {
      expect(isKnownCommand(tokens[0])).toBe(false);
    });

    it(`"opena2a ${example}" reaches the natural-language fallback`, () => {
      expect(example).toBe(example.trim());
      expect(SHELL_SPECIAL.test(example), `"${example}" holds a shell character`).toBe(false);
      expect(shouldTryNaturalLanguageFallback(tokens)).toBe(true);
    });
  }

  it('documents why: "scan" and "detect" are registered commands', () => {
    expect(isKnownCommand('scan')).toBe(true);
    expect(isKnownCommand('detect')).toBe(true);
  });
});
