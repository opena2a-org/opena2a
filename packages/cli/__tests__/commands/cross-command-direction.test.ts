/**
 * Issue #252 — the commands that share opena2a's own scanners must agree in
 * DIRECTION about one directory.
 *
 * The report was: `init` 55, `scan` 96, `review` 20, `benchmark` Certified, for
 * a single directory containing a hardcoded API key, in the same minute. Three
 * of those are legitimate different scopes; one was a defect (#250, benchmark
 * certifying what it never evaluated) and one is a detection gap in the
 * delegated scanner (hackmyagent#316 — `secure` reports CRED-002 as PASSING on
 * a file with a live-shaped key, which is why `scan` is the outlier).
 *
 * Different scopes may disagree on magnitude. They may not disagree on
 * direction: a directory with a critical hardcoded credential must not read as
 * healthy on any surface that evaluates credentials at all.
 *
 * This file unit-tests the scoring predicates. The END-TO-END agreement — real
 * `benchmark()` against a real directory with the real credential scanner — is
 * in `benchmark-credential-mapping.test.ts`, which is what actually catches a
 * credential shape being dropped; hand-built assessments here re-state the
 * code's own constants and cannot disagree with them.
 *
 * `scan` is excluded from direction assertions on purpose. It delegates to
 * `hackmyagent secure`, which reports CRED-002 as PASSING on this fixture shape
 * and scores it 96/100 — verified against the HMA binary with a high-entropy
 * key, so it is not a placeholder filter (hackmyagent#316). Asserting HMA's
 * current behaviour here would either fail this suite for another repo's defect
 * or freeze the bug in place.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';

import { quickCredentialScan } from '../../src/util/credential-patterns.js';
import { scoreCheckIds, gateRating } from '../../src/commands/benchmark.js';

let dirty: string;
let clean: string;

beforeAll(() => {
  // Key generated at runtime: no credential-shaped literal is ever committed,
  // and the entropy rules out a placeholder filter explaining a miss.
  const body = randomBytes(24).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 32);
  dirty = fs.mkdtempSync(path.join(tmpdir(), 'xcmd-dirty-'));
  fs.writeFileSync(path.join(dirty, 'package.json'), '{"name":"d","version":"1.0.0"}\n');
  fs.writeFileSync(path.join(dirty, 'index.js'), `const openai = "sk-${body}";\n`);

  clean = fs.mkdtempSync(path.join(tmpdir(), 'xcmd-clean-'));
  fs.writeFileSync(path.join(clean, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
  fs.writeFileSync(path.join(clean, 'index.js'), 'export const greet = () => "hi";\n');
});

afterAll(() => {
  fs.rmSync(dirty, { recursive: true, force: true });
  fs.rmSync(clean, { recursive: true, force: true });
});

describe('cross-command direction agreement (#252)', () => {
  it('the credential scanner flags the dirty fixture and clears the clean one', () => {
    // The shared source of truth for every surface below. If this inverts,
    // the rest of the test is meaningless, so assert it first.
    return Promise.all([quickCredentialScan(dirty), quickCredentialScan(clean)]).then(([d, c]) => {
      expect(d.map(m => m.findingId)).toContain('CRED-002');
      expect(d.some(m => m.severity === 'critical')).toBe(true);
      expect(c.filter(m => m.findingId.startsWith('CRED'))).toHaveLength(0);
    });
  });

  it('benchmark fails the credential control on the dirty fixture', async () => {
    // #250: this scored Credential Protection 10/10 while `protect` called the
    // same file CRITICAL.
    const matches = await quickCredentialScan(dirty);
    const failing = new Set(matches.map(m => m.findingId));
    const assessment = {
      evaluated: new Set(['CRED-002', 'CRED-003', 'CRED-004']),
      failing: new Set([...failing].filter(id => ['CRED-002', 'CRED-003', 'CRED-004'].includes(id))),
    };
    const score = scoreCheckIds(['CRED-002', 'CRED-003', 'CRED-004'], assessment);
    expect(score.failing).toContain('CRED-002');
    expect(score.compliance).not.toBe(100);
  });

  it('partial coverage with nothing failing tops out at Partial', async () => {
    const assessment = {
      evaluated: new Set(['CRED-002', 'CRED-003', 'CRED-004']),
      failing: new Set<string>(),
    };
    const levelIds = ['CRED-002', 'CRED-003', 'CRED-004', 'PERM-001', 'PROMPT-001'];
    const { rating } = gateRating(scoreCheckIds(levelIds, assessment), 'Certified');
    expect(rating).toBe('Partial');
  });

  it('an EARNED negative rating survives coverage gating', async () => {
    // Gating removes unearned affirmative ratings. Masking `Not Passing` as
    // `Partial` because coverage is incomplete is the same overclaim inverted,
    // and it made `Partial` the only value the field could take.
    const matches = await quickCredentialScan(dirty);
    const assessment = {
      evaluated: new Set(['CRED-002', 'CRED-003', 'CRED-004']),
      failing: new Set(matches.map(m => m.findingId)),
    };
    const levelIds = ['CRED-002', 'CRED-003', 'CRED-004', 'PERM-001', 'PROMPT-001'];
    const { rating } = gateRating(scoreCheckIds(levelIds, assessment), 'Not Passing');
    expect(rating).toBe('Not Passing');
    expect(rating).not.toBe('Partial');
  });

  it('an unevaluated control is never scored as compliant', () => {
    // The #250 fail-open, stated as an invariant rather than an example.
    const assessment = { evaluated: new Set<string>(), failing: new Set<string>() };
    const score = scoreCheckIds(['PERM-001', 'PROMPT-001'], assessment);
    expect(score.compliance).toBeNull();
    expect(score.passing).toHaveLength(0);
    expect(gateRating(score, 'Certified').rating).toBe('Not assessable');
  });

  it('a clean fixture is not dragged down by absent findings', () => {
    // The inverse guard: coverage gating must not make a good result
    // unreachable, only an unearned one.
    const assessment = {
      evaluated: new Set(['CRED-002', 'CRED-003', 'CRED-004']),
      failing: new Set<string>(),
    };
    const score = scoreCheckIds(['CRED-002', 'CRED-003', 'CRED-004'], assessment);
    expect(score.compliance).toBe(100);
    expect(gateRating(score, 'Certified').rating).toBe('Certified');
  });

});
