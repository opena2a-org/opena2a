/**
 * opena2a#258 — the AWS access-key ID and its paired secret were judged by
 * different rules.
 *
 * The migration scanner suppressed placeholder values only for `nameGated`
 * patterns. CRED-005 (secret access key) is name-gated, DRIFT-002 (AKIA access
 * key id) is not, so AWS's own published documentation pair produced exactly
 * one finding: the harmless identifier, with the dangerous half hidden. A user
 * acting on that output migrates the identifier and leaves the secret in place.
 *
 * The canonical `@opena2a/credential-patterns` package already resolved this:
 * KNOWN_EXAMPLE_KEYS lists BOTH halves of the AWS docs pair, source-verified
 * against the IAM User Guide. This suite pins the CLI's local migration scanner
 * to that same decision, and covers the full {example, real} x {id, secret}
 * matrix so a rule applied to one half cannot silently diverge again.
 */
import { afterAll, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { quickCredentialScan, type CredentialMatch } from '../../src/util/credential-patterns.js';

// AWS's published documentation pair (IAM User Guide). Not secrets.
const EXAMPLE_ID = 'AKIAIOSFODNN7EXAMPLE';
const EXAMPLE_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// Non-example, high-entropy equivalents. Assembled at runtime so no
// real-looking 40-char AWS secret literal is committed (GitHub push
// protection rejects those in an aws_secret_access_key context).
const REAL_ID = 'AKIA' + '2X7QNVBTKLMZ4RCD';
const REAL_SECRET = ['Kp7QzR2mNvT4', 'bXwL9sYc1JhG', 'sixdFa8UeZ0i', 'OnPr'].join('');

const created: string[] = [];

function fixture(name: string, content: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `opena2a-aws-${name}-`));
  fs.writeFileSync(path.join(root, 'aws.js'), content, 'utf-8');
  created.push(root);
  return root;
}

afterAll(() => {
  for (const dir of created) fs.rmSync(dir, { recursive: true, force: true });
});

function pairSource(id: string, secret: string): string {
  return `const accessKeyId = '${id}';\nconst secretAccessKey = '${secret}';\n`;
}

function idsOf(matches: CredentialMatch[]): string[] {
  return [...new Set(matches.map(m => m.findingId))].sort();
}

describe('AWS key pair: one rule applied to both halves (#258)', () => {
  it('the secret is 40 chars, so the fixture actually exercises CRED-005', () => {
    // Guard the fixture: CRED-005 requires exactly 40 base64 chars. A
    // miscounted literal would make every assertion below pass vacuously.
    expect(REAL_SECRET).toHaveLength(40);
    expect(EXAMPLE_SECRET).toHaveLength(40);
    expect(REAL_SECRET).not.toMatch(/example|fake|sample/i);
  });

  it('reports NEITHER half of the AWS documentation pair', async () => {
    // The defect: DRIFT-002 fired here while CRED-005 was suppressed.
    const dir = fixture('docs-pair', pairSource(EXAMPLE_ID, EXAMPLE_SECRET));
    expect(idsOf(await quickCredentialScan(dir))).toEqual([]);
  });

  it('reports BOTH halves of a real pair', async () => {
    // Negative control. If suppression is applied too broadly, this is what
    // catches it -- asserting what SURVIVES, not merely what disappeared.
    const dir = fixture('real-pair', pairSource(REAL_ID, REAL_SECRET));
    expect(idsOf(await quickCredentialScan(dir))).toEqual(['CRED-005', 'DRIFT-002']);
  });

  it('reports only the id when the id is real and the secret is an example', async () => {
    const dir = fixture('real-id', pairSource(REAL_ID, EXAMPLE_SECRET));
    expect(idsOf(await quickCredentialScan(dir))).toEqual(['DRIFT-002']);
  });

  it('reports only the secret when the secret is real and the id is an example', async () => {
    const dir = fixture('real-secret', pairSource(EXAMPLE_ID, REAL_SECRET));
    expect(idsOf(await quickCredentialScan(dir))).toEqual(['CRED-005']);
  });

  // --- credential-laundering guard -------------------------------------
  // A substring placeholder test applied to prefix-bearing patterns is a
  // bypass: every one of those patterns admits `_`/`-` in its body, so the
  // greedy match swallows an appended marker, the whole match "contains
  // EXAMPLE", and the finding is dropped -- while `.replace()` restores the
  // key at runtime. Suppression for these patterns is EXACT membership in the
  // canonical known-example set, which cannot be laundered.

  it('reports a live-shaped key with a placeholder token appended', async () => {
    const base = 'sk-ant-api03-' + 'Qz7mNvT4bXwL9sYc1JhG6dFa8UeZ' + 'A'.repeat(67);
    const laundered = [
      `const b = '${base}-SAMPLE'.replace('-SAMPLE','');`,
      `const c = '${base}_FAKE'.slice(0,-5);`,
      `const d = '${base}_DUMMY';`,
      `const e = '${base}_TEST_KEY';`,
      `const f = '${base}-PLACEHOLDER';`,
    ].join('\n');
    const dir = fixture('laundered', laundered + '\n');

    // Each line must still report. Asserting the COUNT (not just presence)
    // catches a rule that suppresses some suffixes and not others.
    const matches = await quickCredentialScan(dir);
    expect(matches.filter(m => m.findingId === 'CRED-001')).toHaveLength(5);
  });

  it('reports a key that incidentally contains a placeholder substring', async () => {
    // Not adversarial: a random 95-char body over [A-Za-z0-9_-] contains
    // "fake" roughly once in 10,000 keys. Those must not vanish silently.
    const key = 'sk-ant-api03-' + 'Qz7mNvT4bfakeL9sYc1JhG6dFa8UeZ' + 'B'.repeat(65);
    const dir = fixture('incidental', `const k = '${key}';\n`);
    expect(idsOf(await quickCredentialScan(dir))).toContain('CRED-001');
  });

  it('reports corpus-style FAKE-marked credentials in malicious fixtures', async () => {
    // The shared adversarial corpus marks its fixture credentials with the
    // literal FAKE. Suppressing on that substring blanks three ratified
    // malicious fixtures and puts this scanner in direct disagreement with
    // hackmyagent, which reports them and prints `opena2a protect .` as the fix.
    const dir = fixture('corpus-shaped', [
      "const t = 'ghp_FAKEexfilTokenForCorpusFixtureOnly0001';",
      "const a = 'AKIAFAKE0EXFIL000000';",
    ].join('\n') + '\n');
    expect(idsOf(await quickCredentialScan(dir))).toEqual(['CRED-003', 'DRIFT-002']);
  });

  it('still reports a real Anthropic key (suppression did not go global)', async () => {
    // The placeholder rule now runs for every pattern, not just name-gated
    // ones. This asserts a prefix-bearing credential with no placeholder
    // marker is untouched by that widening.
    const key = 'sk-ant-api03-' + 'A'.repeat(95);
    const dir = fixture('anthropic', `const apiKey = '${key}';\n`);
    expect(idsOf(await quickCredentialScan(dir))).toContain('CRED-001');
  });

  it('suppresses ONLY exact canonical examples, not look-alikes', async () => {
    // `AKIAIOSFODNN7EXAMPLE` is in KNOWN_EXAMPLE_KEYS and is dropped. A value
    // one character away is not in the set and must still report -- this is
    // what makes the rule unlaunderable.
    const nearMiss = 'AKIAIOSFODNN7EXAMPLF';
    const dir = fixture('near-miss', [
      `const real = '${EXAMPLE_ID}';`,
      `const fake = '${nearMiss}';`,
    ].join('\n') + '\n');

    const matches = await quickCredentialScan(dir);
    expect(matches.map(m => m.value)).toEqual([nearMiss]);
  });
});
