/**
 * Keeps child-process-audit.ts complete (QGF-40.AC5): enumerates every test
 * file under __tests__ whose source statically imports node:child_process
 * and fails when the audit and the tree disagree in either direction. Files
 * that only `vi.mock('node:child_process', ...)` (or `await import(...)` the
 * mocked module) spawn nothing real and are correctly not enumerated: the
 * discriminator is a static `import ... from 'node:child_process'`.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { CHILD_PROCESS_AUDIT } from './child-process-audit.js';

const TESTS_ROOT = __dirname;

const STATIC_IMPORT = /^import\s[^;]*?from\s+['"]node:child_process['"]/m;

function listTestFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return listTestFiles(full);
    return entry.isFile() && entry.name.endsWith('.test.ts') ? [full] : [];
  });
}

describe('child-process spawn audit', () => {
  it('QGF-40.AC5 lists every test file that imports node:child_process, and only those', () => {
    const importers = listTestFiles(TESTS_ROOT)
      .filter(file => STATIC_IMPORT.test(fs.readFileSync(file, 'utf-8')))
      .map(file => path.relative(TESTS_ROOT, file))
      .sort();

    // Symmetric: a new spawning test file must be added to the audit, and an
    // audit entry whose file stopped importing (or moved) must be removed.
    expect(importers).toEqual(Object.keys(CHILD_PROCESS_AUDIT).sort());
  });

  it('records the ceiling concurrent-write.test.ts actually enforces', () => {
    const source = fs.readFileSync(
      path.join(TESTS_ROOT, 'shield', 'concurrent-write.test.ts'),
      'utf-8',
    );
    const match = source.match(/^const MAX_LIVE_CHILDREN = (\d+);$/m);
    expect(match, 'MAX_LIVE_CHILDREN literal not found').not.toBeNull();
    expect(
      CHILD_PROCESS_AUDIT['shield/concurrent-write.test.ts'].maxSimultaneousChildren,
    ).toBe(Number(match![1]));
  });
});
