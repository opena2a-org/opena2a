/**
 * Keeps child-process-audit.ts complete (QGF-40.AC5): enumerates every test
 * file under __tests__ whose source statically imports node:child_process
 * and fails when the audit and the tree disagree in either direction. Files
 * that only `vi.mock('node:child_process', ...)` (or `await import(...)` the
 * mocked module) spawn nothing real and are correctly not enumerated: the
 * discriminator is a static `import ... from 'node:child_process'`.
 *
 * And keeps that file's docstring out of the counting business (QGF-146.AC2):
 * it is read as TEXT here, and a cardinal in the same sentence as the set the
 * table enumerates fails. A count in prose is checked by nobody — the one that
 * used to sit there was wrong on main while every assertion below stayed green
 * — and it has to be rewritten by every delivery that changes the set, which
 * is what made two of them collide. The symmetric assertion is the half that
 * works, so QGF-146.AC3 re-derives it and pins the pieces it is made of.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { CHILD_PROCESS_AUDIT } from './child-process-audit.js';

const TESTS_ROOT = __dirname;

const STATIC_IMPORT = /^import\s[^;]*?from\s+['"]node:child_process['"]/m;

/** The audited file itself, read as text — never a fixture copy of it. */
const AUDIT_SOURCE = path.join(TESTS_ROOT, 'child-process-audit.ts');
/** This file, read as text, so QGF-146.AC3 can pin what it still asserts. */
const THIS_SOURCE = path.join(TESTS_ROOT, 'child-process-audit.test.ts');

/** An ASCII numeral, or an English number word one through twenty. */
const CARDINAL =
  /\b(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty)\b/i;

/** A name for the set the table enumerates. */
const AUDITED_SET = /\b(?:spawners?|importers?|population)\b/i;

function listTestFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return listTestFiles(full);
    return entry.isFile() && entry.name.endsWith('.test.ts') ? [full] : [];
  });
}

/**
 * The sentences of a file's leading block comment, markers stripped. A blank
 * comment line ends a paragraph; inside one, a sentence ends at `.`, `!` or
 * `?` followed by whitespace and a capital — which keeps `import ... from`
 * and `shield/llm.test.ts and ...` in one piece rather than splitting prose
 * at every filename.
 */
function leadingCommentSentences(file: string): string[] {
  const block = /^\/\*\*([\s\S]*?)\*\//.exec(fs.readFileSync(file, 'utf-8'));
  if (block === null) throw new Error(`${path.basename(file)} has no leading block comment`);
  const paragraphs = [''];
  for (const raw of block[1].split('\n')) {
    const line = raw.replace(/^\s*\*\s?/, '').trim();
    if (line === '') paragraphs.push('');
    else paragraphs[paragraphs.length - 1] = `${paragraphs[paragraphs.length - 1]} ${line}`.trim();
  }
  return paragraphs
    .flatMap(paragraph => paragraph.split(/(?<=[.!?])\s+(?=[A-Z])/))
    .filter(sentence => sentence !== '');
}

/** Where one testcase of this file ends and the next begins. */
const TESTCASE_BOUNDARY = /\n {2}it\(/;

/** One testcase's source, from its `it(` to the next one in this file. */
function testcaseSource(source: string, titlePrefix: string): string {
  const chunk = source.split(TESTCASE_BOUNDARY).find(part => part.startsWith(`'${titlePrefix}`));
  if (chunk === undefined) throw new Error(`no testcase starting "${titlePrefix}" in this file`);
  return chunk;
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

  // The table above is bound to the tree and cannot rot. A docstring sentence
  // giving the size of that table is bound to nothing: the one that used to be
  // there was wrong on main and nothing went red. It also had to be rewritten
  // by every delivery that changed the set, which is how two of them came to
  // collide on a file whose rows merge cleanly. So: no cardinal beside the
  // name of the set. Nothing here asserts how many entries the table holds —
  // that number is written down nowhere, which is the point.
  it('QGF-146.AC2 the audit docstring gives no count of the set the table enumerates', () => {
    const offenders = leadingCommentSentences(AUDIT_SOURCE).filter(
      sentence => CARDINAL.test(sentence) && AUDITED_SET.test(sentence),
    );

    expect(
      offenders,
      'child-process-audit.ts counts its own audited set in prose. The table is the one place ' +
        'that set is written down: a row is a local edit, a shared sentence is not. Offending ' +
        `sentence(s): ${offenders.map(sentence => JSON.stringify(sentence)).join(' | ')}`,
    ).toEqual([]);
  });

  // Nothing in this delivery weakens the assertion above. It still enumerates
  // the tree, still compares both ways for equality, still reads the ceiling
  // out of concurrent-write.test.ts — pinned here as source, since a test
  // cannot observe its own history. The equality is re-derived at the
  // delivered commit, where this contract's own new spawning file is one of
  // the entries, and neither side is compared to a number written anywhere.
  it('QGF-146.AC3 the symmetric assertion still binds the table to the tree, both ways', () => {
    const importers = listTestFiles(TESTS_ROOT)
      .filter(file => STATIC_IMPORT.test(fs.readFileSync(file, 'utf-8')))
      .map(file => path.relative(TESTS_ROOT, file))
      .sort();
    const audited = Object.keys(CHILD_PROCESS_AUDIT).sort();

    expect(
      importers.filter(file => !audited.includes(file)),
      'imports node:child_process and is missing from CHILD_PROCESS_AUDIT',
    ).toEqual([]);
    expect(
      audited.filter(file => !importers.includes(file)),
      'is audited but no longer imports node:child_process (moved, renamed or stopped spawning)',
    ).toEqual([]);
    expect(importers).toEqual(audited);
    // The merge cell this contract adds spawns git, so it audits itself.
    expect(importers).toContain('child-process-audit-merge.test.ts');

    const source = fs.readFileSync(THIS_SOURCE, 'utf-8');
    const squash = (text: string) => text.replace(/\s+/g, '');
    const preamble = source.split(TESTCASE_BOUNDARY)[0];
    const enumeration = testcaseSource(source, 'QGF-40.AC5');
    const ceiling = testcaseSource(source, 'records the ceiling');

    const parts: [string, string, string][] = [
      ['the preamble', preamble, `const STATIC_IMPORT = /^import\\s[^;]*?from\\s+['"]node:child_process['"]/m;`],
      ['the QGF-40.AC5 testcase', enumeration, 'listTestFiles(TESTS_ROOT)'],
      ['the QGF-40.AC5 testcase', enumeration, `STATIC_IMPORT.test(fs.readFileSync(file, 'utf-8'))`],
      ['the QGF-40.AC5 testcase', enumeration, 'expect(importers).toEqual(Object.keys(CHILD_PROCESS_AUDIT).sort());'],
      ['the ceiling testcase', ceiling, `source.match(/^const MAX_LIVE_CHILDREN = (\\d+);$/m)`],
      ['the ceiling testcase', ceiling, `CHILD_PROCESS_AUDIT['shield/concurrent-write.test.ts'].maxSimultaneousChildren`],
      ['the ceiling testcase', ceiling, 'toBe(Number(match![1]))'],
    ];
    for (const [where, chunk, piece] of parts) {
      expect(
        squash(chunk),
        `${where} of child-process-audit.test.ts no longer contains ${piece} — the symmetric ` +
          'assertion is the half of this audit that cannot go stale; weaken it deliberately or ' +
          'not at all',
      ).toContain(squash(piece));
    }
  });
});
