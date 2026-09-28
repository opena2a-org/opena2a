/**
 * Keeps the pre-push self-scan green against NEMO-005 (issue #322).
 *
 * The pinned scanner (`hackmyagent secure --ci`) reports NEMO-005 CRITICAL on
 * any line that calls `exec(`/`execSync(` beside a template literal
 * interpolating a variable named like user input. It reads lines, not calls,
 * so a test that built a RegExp from a template interpolating `setName` and
 * called RegExp#exec on the same line tripped it and blocked every push. The scanner also stops after 200 files, so a
 * hit outside that window passes the gate today and blocks it after an
 * unrelated file is added.
 *
 * This walks every JS/TS file in the repository with the same line predicate,
 * so a new hit fails `npm test` instead of the gate. A real shell exec
 * belongs in execFile/spawn with an argument array; a regex match belongs in
 * String#match.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const repoRoot = path.resolve(__dirname, '..', '..', '..');

const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', '.turbo', 'coverage']);
const EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs']);

// NEMO-005's three line conditions, as the pinned scanner applies them.
const CALLS_EXEC = /\bexec(Sync)?\s*\(/;
const CALLS_EXEC_FILE = /\bexecFile/;
const INTERPOLATES_INPUT_LIKE = /`[^`]*\$\{[^}]*(name|Name|id|Id|input|arg|param|flag|option)/i;

function walk(dir: string, out: string[]): void {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(path.join(dir, entry.name), out);
    } else if (entry.isFile() && EXTENSIONS.has(path.extname(entry.name))) {
      out.push(path.join(dir, entry.name));
    }
  }
}

describe('self-scan NEMO-005 (exec with interpolated input)', () => {
  it('no JS/TS line in the repository matches the scanner predicate', () => {
    const files: string[] = [];
    walk(repoRoot, files);
    expect(files.length).toBeGreaterThan(200);

    const hits: string[] = [];
    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf-8').split('\n');
      lines.forEach((line, i) => {
        if (CALLS_EXEC.test(line) && !CALLS_EXEC_FILE.test(line) && INTERPOLATES_INPUT_LIKE.test(line)) {
          hits.push(`${path.relative(repoRoot, file)}:${i + 1}`);
        }
      });
    }
    expect(hits).toEqual([]);
  });

  it('the predicate still recognises the line that blocked the gate', () => {
    // Assembled from parts so this file's own lines never match the predicate.
    const blocked = [
      'const setDecl = new RegExp(`const $',
      '{setName}\\s*=`).exec(source)!;',
    ].join('');
    expect(CALLS_EXEC.test(blocked)).toBe(true);
    expect(CALLS_EXEC_FILE.test(blocked)).toBe(false);
    expect(INTERPOLATES_INPUT_LIKE.test(blocked)).toBe(true);
  });
});
