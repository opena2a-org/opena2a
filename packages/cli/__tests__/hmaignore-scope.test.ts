import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

// ---------------------------------------------------------------------------
// Scope guard for the repository-root .hmaignore.
//
// The root .hmaignore narrows what `hackmyagent secure --ci` reads, so its
// contents are a security-relevant surface: a silently added rule is a
// suppressed finding. This test pins the file to its ruled shape — exactly
// two single-file exclusions, each carrying its own check-id + public-issue
// comment — so that ANY change to the exclusion set shows up as a test diff
// and has to be re-approved, and so that a rule that matches nothing (or a
// blanket negation/directory rule) cannot land at all.
//
// The audit logic is exercised in both directions below: against the real
// tree, and against fixture contents this file builds itself (see the
// "rejects" cases), so the guard is proven to fail on each offending shape
// rather than being green only by construction against the current tree.
// ---------------------------------------------------------------------------

const repoRoot = path.resolve(__dirname, '..', '..', '..');
const rootIgnorePath = path.join(repoRoot, '.hmaignore');

/** The two ruled exclusions, verbatim and in file order. */
const RULED_PATHS = [
  'packages/cli/scripts/shield-lock-trace-loop.ts',
  'packages/cli/__tests__/shield/events.test.ts',
];

/** e.g. NEMO-007, SKILL-023 — the id of the check the rule suppresses. */
const CHECK_ID = /\b[A-Z][A-Z0-9]*-\d+\b/;
/** A public issue citation: a github issues URL or a bare #NNN reference. */
const ISSUE_REF = /(github\.com\/[^\s)]+\/issues\/\d+)|((^|[\s(])#\d+\b)/;

interface Offender {
  line: number;
  text: string;
  reason:
    | 'negation-line'
    | 'not-an-existing-file'
    | 'no-preceding-comment'
    | 'comment-lacks-check-id'
    | 'comment-lacks-issue-ref'
    | 'rule-under-src';
}

/** A rule line together with the contiguous comment block directly above it. */
interface Rule {
  line: number;
  rulePath: string;
  comments: string[];
}

function parseRules(content: string): { rules: Rule[]; offenders: Offender[] } {
  const lines = content.split('\n');
  const rules: Rule[] = [];
  const offenders: Offender[] = [];

  lines.forEach((raw, idx) => {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) return;
    if (line.startsWith('!')) {
      offenders.push({ line: idx + 1, text: line, reason: 'negation-line' });
      return;
    }
    const comments: string[] = [];
    for (let j = idx - 1; j >= 0; j--) {
      const above = lines[j].trim();
      if (!above.startsWith('#')) break;
      comments.unshift(above);
    }
    rules.push({ line: idx + 1, rulePath: line, comments });
  });

  return { rules, offenders };
}

function isExistingFile(rulePath: string): boolean {
  try {
    return fs.statSync(path.join(repoRoot, rulePath)).isFile();
  } catch {
    return false;
  }
}

function auditHmaIgnore(content: string): Offender[] {
  const { rules, offenders } = parseRules(content);

  for (const rule of rules) {
    const entry = { line: rule.line, text: rule.rulePath };
    if (!isExistingFile(rule.rulePath)) {
      offenders.push({ ...entry, reason: 'not-an-existing-file' });
    }
    if (rule.comments.length === 0) {
      offenders.push({ ...entry, reason: 'no-preceding-comment' });
    } else {
      const block = rule.comments.join('\n');
      if (!CHECK_ID.test(block)) {
        offenders.push({ ...entry, reason: 'comment-lacks-check-id' });
      }
      if (!ISSUE_REF.test(block)) {
        offenders.push({ ...entry, reason: 'comment-lacks-issue-ref' });
      }
    }
    if (rule.rulePath.startsWith('packages/cli/src/')) {
      offenders.push({ ...entry, reason: 'rule-under-src' });
    }
  }

  return offenders;
}

const rulePaths = (content: string): string[] =>
  parseRules(content).rules.map(r => r.rulePath);

describe('root .hmaignore scope guard (real repository state)', () => {
  const content = fs.readFileSync(rootIgnorePath, 'utf-8');

  it('OPA-08.AC4 (a) no line of the root .hmaignore begins with !', () => {
    for (const line of content.split('\n')) {
      expect(line.trim().startsWith('!')).toBe(false);
    }
  });

  it('OPA-08.AC4 (b) every rule line is a single path naming a file that exists', () => {
    for (const rulePath of rulePaths(content)) {
      expect(isExistingFile(rulePath), `${rulePath} is not an existing file`).toBe(true);
    }
  });

  it('OPA-08.AC4 (c) every rule line is preceded by comment lines naming a check id and an issue reference', () => {
    for (const rule of parseRules(content).rules) {
      const block = rule.comments.join('\n');
      expect(rule.comments.length, `${rule.rulePath} has no preceding comment`).toBeGreaterThan(0);
      expect(block).toMatch(CHECK_ID);
      expect(block).toMatch(ISSUE_REF);
    }
  });

  it('OPA-08.AC4 (d) no rule path is under packages/cli/src/', () => {
    for (const rulePath of rulePaths(content)) {
      expect(rulePath.startsWith('packages/cli/src/')).toBe(false);
    }
  });

  it('OPA-08.AC4 (e) packages/cli/.hmaignore does not exist', () => {
    expect(fs.existsSync(path.join(repoRoot, 'packages', 'cli', '.hmaignore'))).toBe(false);
  });

  it('OPA-08.AC4 (f) the rule list equals the two ruled paths verbatim', () => {
    expect(rulePaths(content)).toEqual(RULED_PATHS);
  });

  it('OPA-08.AC4 the full audit reports no offender on the committed file', () => {
    expect(auditHmaIgnore(content)).toEqual([]);
  });
});

describe('scope guard audit (fixture contents built here, both directions)', () => {
  const ruledComment = [
    '# NEMO-000: reason for the exclusion.',
    '# Triaged: github.com/opena2a-org/opena2a/issues/188',
  ];
  const ruledFixture = [
    ...ruledComment,
    RULED_PATHS[0],
    '',
    ...ruledComment,
    RULED_PATHS[1],
    '',
  ].join('\n');

  it('OPA-08.AC5 rejects a fixture carrying a ! negation line', () => {
    const fixture = `${ruledFixture}!NEMO-007\n`;
    expect(auditHmaIgnore(fixture).map(o => o.reason)).toContain('negation-line');
  });

  it('OPA-08.AC5 rejects a fixture carrying a directory-level rule', () => {
    const fixture = [...ruledComment, 'packages/cli/__tests__', ''].join('\n');
    expect(auditHmaIgnore(fixture).map(o => o.reason)).toContain('not-an-existing-file');
  });

  it('OPA-08.AC5 rejects a fixture whose rule names a non-existent file', () => {
    const fixture = [...ruledComment, 'packages/cli/no-such-file.ts', ''].join('\n');
    expect(auditHmaIgnore(fixture).map(o => o.reason)).toContain('not-an-existing-file');
  });

  it('OPA-08.AC5 rejects a fixture whose rule lacks a preceding check-id/issue comment', () => {
    const bare = `${RULED_PATHS[0]}\n`;
    expect(auditHmaIgnore(bare).map(o => o.reason)).toContain('no-preceding-comment');

    const noCheckId = ['# excluded because reasons: see issue #188', RULED_PATHS[0], ''].join('\n');
    expect(auditHmaIgnore(noCheckId).map(o => o.reason)).toContain('comment-lacks-check-id');

    const noIssue = ['# NEMO-007: excluded because reasons.', RULED_PATHS[0], ''].join('\n');
    expect(auditHmaIgnore(noIssue).map(o => o.reason)).toContain('comment-lacks-issue-ref');
  });

  it('OPA-08.AC5 rejects a fixture carrying a rule under packages/cli/src/', () => {
    const fixture = [...ruledComment, 'packages/cli/src/index.ts', ''].join('\n');
    expect(auditHmaIgnore(fixture).map(o => o.reason)).toContain('rule-under-src');
  });

  it('OPA-08.AC5 accepts a fixture matching the ruled shape', () => {
    expect(auditHmaIgnore(ruledFixture)).toEqual([]);
    expect(rulePaths(ruledFixture)).toEqual(RULED_PATHS);
  });
});
