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
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { matchIntent } from '../../src/natural/intent-map.js';

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
