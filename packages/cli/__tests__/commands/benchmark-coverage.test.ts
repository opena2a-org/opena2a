/**
 * Issue #250 — `benchmark` must not certify what it did not evaluate.
 *
 * The original scoring marked a control passing when no finding *mentioned* its
 * check ID. The only source it consulted (`HardeningScanner`) emits GIT-* ids
 * and evaluates none of the 39 OASB L1 check IDs, so every L1 control "passed"
 * by never being assessed and an empty directory came back `Certified`.
 *
 * A compliance rating is evidence a user hands to a third party. Asserting a
 * control passed without evaluating it is fabrication, so these tests pin
 * coverage-gated scoring: score only what was evaluated, disclose the rest,
 * and never award a passing rating over incomplete coverage.
 */
import { describe, it, expect, vi, beforeEach, afterEach, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

/** OASB L1 vocabulary, trimmed to what these tests exercise. */
const L1_IDS = [
  'CRED-002', 'CRED-003', 'CRED-004', 'SEM-CRED-001', 'MCP-006',
  'PERM-001', 'PERM-002', 'PROMPT-001', 'DEP-001', 'LOG-001',
];
/** The level vocabulary the stub serves; a test may swap it with the catalogue. */
let levelIds: string[] = L1_IDS;

const CATEGORIES = [
  {
    id: 1, name: 'Identity & Provenance', description: '',
    // Deliberately has no L1 controls — the source of the "0% NEEDS WORK"
    // line that appeared next to "L1 100%".
    controls: [{ id: 'C1', name: 'x', category: 'ident', level: 'L2', scored: true, description: '', checkIds: ['SEM-ID-001'] }],
  },
  {
    id: 5, name: 'Credential Protection', description: '',
    controls: [
      { id: 'C5a', name: 'x', category: 'cred', level: 'L1', scored: true, description: '', checkIds: ['CRED-002', 'CRED-003', 'CRED-004'] },
      { id: 'C5b', name: 'y', category: 'cred', level: 'L1', scored: true, description: '', checkIds: ['SEM-CRED-001', 'MCP-006', 'LOG-001'] },
    ],
  },
  {
    id: 2, name: 'Capability & Authorization', description: '',
    controls: [{ id: 'C2', name: 'x', category: 'cap', level: 'L1', scored: true, description: '', checkIds: ['PERM-001', 'PERM-002'] }],
  },
];

/** Findings the HardeningScanner returns. Configured per test. */
let hardeningFindings: Array<Record<string, unknown>> = [];
/** Credential matches quickCredentialScan returns. Configured per test. */
let credentialMatches: Array<Record<string, unknown>> = [];

vi.mock('hackmyagent', () => ({
  OASB_1_NAME: 'OASB-1',
  OASB_1_VERSION: '1.0',
  OASB_1_CATEGORIES: CATEGORIES,
  getControlsForLevel: (lvl: string) =>
    CATEGORIES.flatMap(c => c.controls).filter(c => (lvl === 'L1' ? c.level === 'L1' : true)),
  getCheckIdsForLevel: () => levelIds,
  calculateRating: (l1: number) => (l1 === 100 ? 'Certified' : l1 >= 90 ? 'Passing' : 'Not Passing'),
  HardeningScanner: class {
    async scan() { return { findings: hardeningFindings }; }
  },
}));

/** Lets one test simulate a credential scan that cannot run. */
const credentialScanControl = { get shouldThrow() { return false; } };

vi.mock('../../src/util/credential-patterns.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/credential-patterns.js')>();
  return {
    ...actual,
    quickCredentialScan: async () => {
      if (credentialScanControl.shouldThrow) throw new Error('scan unavailable');
      return credentialMatches;
    },
  };
});

const { benchmark } = await import('../../src/commands/benchmark.js');

/** Both scans are mocked, so the target's content does not matter; it only
 *  has to exist, because `benchmark` refuses a missing target before scanning. */
const target = fs.mkdtempSync(path.join(tmpdir(), 'bench-coverage-'));

afterAll(() => {
  fs.rmSync(target, { recursive: true, force: true });
});

async function runJson(): Promise<Record<string, any>> {
  let out = '';
  const spy = vi.spyOn(process.stdout, 'write').mockImplementation((c: any) => { out += c; return true; });
  await benchmark({ targetDir: target, format: 'json' });
  spy.mockRestore();
  return JSON.parse(out);
}

async function runText(): Promise<string> {
  let out = '';
  const spy = vi.spyOn(process.stdout, 'write').mockImplementation((c: any) => { out += c; return true; });
  await benchmark({ targetDir: target, verbose: true });
  spy.mockRestore();
  return out;
}

beforeEach(() => {
  hardeningFindings = [];
  credentialMatches = [];
});

const DEFAULT_CATEGORIES = [...CATEGORIES];

afterEach(() => {
  CATEGORIES.splice(0, CATEGORIES.length, ...DEFAULT_CATEGORIES);
  levelIds = L1_IDS;
});

/** One L1 category whose single control lists `checkIds`. */
function category(id: number, name: string, checkIds: string[]): (typeof CATEGORIES)[number] {
  return {
    id, name, description: '',
    controls: [{ id: `C${id}`, name: 'x', category: name, level: 'L1', scored: true, description: '', checkIds }],
  };
}

/**
 * A catalogue in which, as in the real OASB-1 L1 set, one check id belongs to
 * controls in more than one category: PERM-001, TOOL-001, PROMPT-001, NET-003
 * and LOG-001 are each listed twice or three times. 17 category entries, 11
 * distinct ids, and every id in the level sits in at least one category.
 */
function useSharedCatalogue(): void {
  CATEGORIES.splice(0, CATEGORIES.length,
    category(2, 'Capability & Authorization', ['PERM-001', 'TOOL-001']),
    category(3, 'Input Security', ['PROMPT-001', 'NET-003']),
    category(4, 'Output Security', ['TOOL-001', 'NET-003', 'OUT-001']),
    category(5, 'Credential Protection', ['CRED-002', 'CRED-003', 'CRED-004', 'LOG-001']),
    category(8, 'Memory & Context Integrity', ['PROMPT-001']),
    category(9, 'Operational Security', ['PERM-001', 'NET-003', 'OPS-001']),
    category(10, 'Monitoring & Response', ['LOG-001', 'MON-001']),
  );
  levelIds = [...new Set(CATEGORIES.flatMap(c => c.controls.flatMap(ctl => ctl.checkIds)))];
}

/** Hardening findings that evaluate `ids`, failing the ones in `failing`. */
function evaluate(ids: string[], failing: string[]): Array<Record<string, unknown>> {
  return ids.map(id => ({ checkId: id, passed: !failing.includes(id), severity: 'info' }));
}

/** The header's `(X of Y ... evaluated)` figures. */
function headerCounts(text: string): { evaluated: number; total: number } {
  const m = text.match(/^\s*L1:.*\((\d+) of (\d+)[^)]*evaluated\)/m);
  expect(m, 'L1 score line').not.toBeNull();
  return { evaluated: Number(m![1]), total: Number(m![2]) };
}

/** The `(X of Y ... assessed` figures of every category line, summed. */
function categorySums(text: string): { assessed: number; total: number } {
  let assessed = 0;
  let total = 0;
  for (const line of text.split('\n')) {
    const m = line.match(/^ {4}\d+\. .*\((\d+) of (\d+)[^)]*assessed/);
    if (!m) continue;
    assessed += Number(m[1]);
    total += Number(m[2]);
  }
  return { assessed, total };
}

/** The "Failing controls to address" entries: category name -> ids. */
function failingList(text: string): Map<string, string[]> {
  const lines = text.split('\n');
  const start = lines.findIndex(l => l.trim() === 'Failing controls to address:');
  const listed = new Map<string, string[]>();
  if (start === -1) return listed;
  for (const line of lines.slice(start + 1)) {
    const m = line.match(/^ {4}- (.+?): (.+)$/);
    if (!m) break;
    listed.set(m[1], m[2].split(', '));
  }
  return listed;
}

function failingCount(text: string): number {
  const m = text.match(/^\s*Failing:\s+(\d+)$/m);
  expect(m, 'Failing line').not.toBeNull();
  return Number(m![1]);
}

describe('benchmark header, categories and failing list add up', () => {
  it('category assessed figures sum to the header when a check id sits in two categories', async () => {
    useSharedCatalogue();
    hardeningFindings = evaluate(
      ['PERM-001', 'TOOL-001', 'NET-003', 'PROMPT-001', 'LOG-001', 'OPS-001'],
      ['PERM-001', 'NET-003', 'OPS-001'],
    );
    const text = await runText();

    const header = headerCounts(text);
    // CRED-002/003/004 come from the credential scan.
    expect(header).toEqual({ evaluated: 9, total: 11 });
    expect(categorySums(text)).toEqual({ assessed: header.evaluated, total: header.total });

    const listed = failingList(text);
    expect([...listed.values()].flat().length).toBe(failingCount(text));
    expect(failingCount(text)).toBe(3);
  });

  it('lists every failing category, and as many ids as the Failing line counts', async () => {
    useSharedCatalogue();
    hardeningFindings = evaluate(
      ['PERM-001', 'PROMPT-001', 'OUT-001', 'CRED-003', 'MON-001'],
      ['PERM-001', 'PROMPT-001', 'OUT-001', 'CRED-003', 'MON-001'],
    );
    const text = await runText();

    const listed = failingList(text);
    expect([...listed.keys()]).toEqual([
      'Capability & Authorization',
      'Input Security',
      'Output Security',
      'Credential Protection',
      'Monitoring & Response',
    ]);
    expect([...listed.values()].flat().length).toBe(failingCount(text));
    expect(failingCount(text)).toBe(5);
  });

  it('the score line says the percentage is over evaluated controls', async () => {
    const text = await runText();
    expect(text).toMatch(/^\s*L1:\s+\d+% of evaluated controls \(\d+ of \d+ evaluated\)$/m);
  });

  it('names where a shared check id is counted, and explains it only when one exists', async () => {
    const note = 'Controls per category can repeat a check id; the level total counts each id once.';
    expect(await runText()).not.toContain(note);

    useSharedCatalogue();
    hardeningFindings = evaluate(['PERM-001', 'TOOL-001', 'NET-003'], []);
    const text = await runText();
    expect(text).toContain(note);
    expect(text).toMatch(/Operational Security: .*2 shared with Capability & Authorization, Input Security\)/);
    expect(text).toMatch(/Memory & Context Integrity: counted under Input Security/);
  });

  it('JSON categories add up to coverage and summary', async () => {
    useSharedCatalogue();
    hardeningFindings = evaluate(['PERM-001', 'NET-003', 'OPS-001', 'LOG-001'], ['PERM-001', 'NET-003']);
    const r = await runJson();
    const sum = (f: (c: any) => number) => r.categories.reduce((n: number, c: any) => n + f(c), 0);

    expect(sum(c => c.evaluated)).toBe(r.coverage.evaluated);
    expect(sum(c => c.totalChecks)).toBe(r.coverage.total);
    expect(sum(c => c.failing.length)).toBe(r.summary.failingControls);
    expect(r.coverage.total).toBe(11);

    const memory = r.categories.find((c: any) => c.id === 8);
    expect(memory.sharedCheckIds).toEqual([{ checkId: 'PROMPT-001', countedUnder: 'Input Security' }]);
  });
});

describe('benchmark coverage gating (#250)', () => {
  it('an empty project is never Certified', async () => {
    // The old code called this 100% / Certified over 39 controls it never
    // assessed. The credential scan legitimately evaluates CRED-002/003/004
    // here (an empty tree really has no hardcoded keys), so the honest answer
    // is Partial over 3 of 10 — not Certified, and not a fabricated 100%.
    const r = await runJson();
    expect(r.rating).not.toBe('Certified');
    expect(r.rating).not.toBe('Passing');
    expect(r.rating).toBe('Partial');
    expect(r.coverage.evaluated).toBe(3);
    expect(r.coverage.notEvaluated).toBe(L1_IDS.length - 3);
  });

  it('is Not assessable when no source could evaluate anything', async () => {
    // Fail closed: a credential scan that cannot run must withdraw its
    // coverage rather than leave those controls looking assessed.
    const spy = vi.spyOn(credentialScanControl, 'shouldThrow', 'get').mockReturnValue(true);
    const r = await runJson();
    spy.mockRestore();
    expect(r.coverage.evaluated).toBe(0);
    expect(r.rating).toBe('Not assessable');
    expect(r.compliance.l1).toBeNull();
  });

  it('unevaluated controls are never counted as passing', async () => {
    hardeningFindings = [{ checkId: 'GIT-001', passed: false, severity: 'low' }];
    const r = await runJson();
    // GIT-001 is not an OASB control, so the hardening scanner contributed no
    // OASB coverage at all — the defect that made every L1 control "pass".
    // Only the credential vocabulary is genuinely evaluated.
    expect(r.coverage.evaluated).toBe(3);
    expect(r.coverage.notEvaluatedIds).toEqual(
      expect.arrayContaining(['PERM-001', 'PERM-002', 'PROMPT-001', 'DEP-001', 'LOG-001']),
    );
    // The seven unassessed controls are absent from BOTH sides of the ratio.
    expect(r.compliance.l1).toBe(100);
    expect(r.rating).not.toBe('Certified');
  });

  it('a hardcoded credential fails Credential Protection instead of scoring 100%', async () => {
    // quickCredentialScan is what init/protect already use, and CRED-002 is in
    // the OASB L1 vocabulary — so this control is genuinely evaluable today.
    credentialMatches = [{ findingId: 'CRED-002', severity: 'critical', file: 'index.js', line: 1 }];
    const r = await runJson();

    const cred = r.categories.find((c: any) => c.id === 5);
    expect(cred.compliance).not.toBe(100);
    expect(cred.failing).toContain('CRED-002');
    expect(r.rating).not.toBe('Certified');
  });

  it('a clean project still cannot be Certified while coverage is partial', async () => {
    // No credential findings: CRED-002/003/004 evaluated and passing. But the
    // other L1 ids were never assessed, so a passing rating would overclaim.
    const r = await runJson();
    expect(r.coverage.evaluated).toBeLessThan(L1_IDS.length);
    expect(r.rating).not.toBe('Certified');
  });

  it('categories with no applicable controls report n/a, not 0%', async () => {
    // Category 1 has only an L2 control; at L1 it is not applicable. The old
    // code rendered totalChecks === 0 as "0% [NEEDS WORK]" beside "L1 100%".
    const r = await runJson();
    const ident = r.categories.find((c: any) => c.id === 1);
    expect(ident.applicable).toBe(false);
    expect(ident.compliance).toBeNull();

    const text = await runText();
    expect(text).toMatch(/Identity & Provenance:\s*n\/a/);
    expect(text).not.toMatch(/Identity & Provenance:\s*0%/);
  });

  it('discloses coverage on the score line rather than implying a full assessment', async () => {
    credentialMatches = [];
    const text = await runText();
    // The org rule: an absolute label may not sit beside an undisclosed scope.
    expect(text).toMatch(/\d+ of \d+ .*evaluated/i);
  });

  it('names what was not evaluated so the number is interpretable', async () => {
    const r = await runJson();
    expect(Array.isArray(r.coverage.notEvaluatedIds)).toBe(true);
    expect(r.coverage.notEvaluatedIds).toContain('PERM-001');
  });

  it('full coverage with everything passing can still reach Certified', async () => {
    // The gate must not make a good result unreachable — only unearned ones.
    hardeningFindings = L1_IDS.map(id => ({ checkId: id, passed: true, severity: 'info' }));
    const r = await runJson();
    expect(r.coverage.evaluated).toBe(L1_IDS.length);
    expect(r.compliance.l1).toBe(100);
    expect(r.rating).toBe('Certified');
  });

  it('full coverage with a failure does not certify', async () => {
    hardeningFindings = L1_IDS.map(id => ({ checkId: id, passed: id !== 'PERM-001', severity: 'info' }));
    const r = await runJson();
    expect(r.coverage.evaluated).toBe(L1_IDS.length);
    expect(r.compliance.l1).toBeLessThan(100);
    expect(r.rating).not.toBe('Certified');
  });
});
