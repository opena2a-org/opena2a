/**
 * Benign FPR regression suite — opena2a-cli credential detection.
 *
 * Mirrors HMA's `__tests__/nanomind-core/benign-fp-regression.test.ts` (10
 * hard-negative fixtures, zero high/critical gate). Drives the credential
 * detection layer (`quickCredentialScan` in `src/util/credential-patterns.ts`)
 * — the primary detector that motivated the audit-bundle fixture-exclusion
 * fix.
 *
 * Adding a new check or pattern: run this suite BEFORE merging. A new FP
 * here is a regression — fix the root cause (tighten the pattern, add a
 * skip condition) before shipping.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { quickCredentialScan, type CredentialMatch } from '../src/util/credential-patterns.js';

const HIGH_CRITICAL = new Set(['high', 'critical']);

function getHighCriticalFindings(matches: CredentialMatch[]): CredentialMatch[] {
  return matches.filter((m) => HIGH_CRITICAL.has(m.severity));
}

function makeFixture(name: string, files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `opena2a-benign-${name}-`));
  for (const [relPath, content] of Object.entries(files)) {
    const abs = path.join(root, relPath);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf-8');
  }
  return root;
}

describe('benign FPR regression — credential detection', () => {
  const created: string[] = [];

  function fixture(name: string, files: Record<string, string>): string {
    const dir = makeFixture(name, files);
    created.push(dir);
    return dir;
  }

  afterAll(() => {
    for (const dir of created) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        // best-effort cleanup
      }
    }
  });

  it('b01: empty package.json — no findings', () => {
    const dir = fixture('b01', { 'package.json': '{}\n' });
    expect(getHighCriticalFindings(quickCredentialScan(dir))).toEqual([]);
  });

  it('b02: README mentions API_KEY without an actual key — no findings', () => {
    const dir = fixture('b02', {
      'README.md': '# App\n\nSet `API_KEY` in your environment before running.\n',
    });
    expect(getHighCriticalFindings(quickCredentialScan(dir))).toEqual([]);
  });

  it('b03: .env.example with placeholder values — no findings', () => {
    const dir = fixture('b03', {
      '.env.example': [
        'ANTHROPIC_API_KEY=your-key-here',
        'OPENAI_API_KEY=sk-replace-me',
        'GITHUB_TOKEN=ghp_change_this',
      ].join('\n') + '\n',
    });
    expect(getHighCriticalFindings(quickCredentialScan(dir))).toEqual([]);
  });

  it('b04: code reads keys via process.env — no findings', () => {
    const dir = fixture('b04', {
      'app.js': [
        "const apiKey = process.env.ANTHROPIC_API_KEY;",
        "const githubToken = process.env.GITHUB_TOKEN;",
        "if (!apiKey) throw new Error('missing ANTHROPIC_API_KEY');",
      ].join('\n') + '\n',
    });
    expect(getHighCriticalFindings(quickCredentialScan(dir))).toEqual([]);
  });

  it('b05: comment showing key shape but no real key — no findings', () => {
    const dir = fixture('b05', {
      'docs.md': [
        '# How to set credentials',
        '',
        'Anthropic keys look like `sk-ant-api03-...` (~108 chars).',
        'GitHub PATs look like `ghp_...`.',
      ].join('\n') + '\n',
    });
    expect(getHighCriticalFindings(quickCredentialScan(dir))).toEqual([]);
  });

  it('b06: test fixture with key-shaped content under test/ — no findings (SKIP_DIRS)', () => {
    const dir = fixture('b06', {
      'test/fixture.js': [
        "const fakeKey = 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';",
      ].join('\n') + '\n',
    });
    expect(getHighCriticalFindings(quickCredentialScan(dir))).toEqual([]);
  });

  it('b07: vendored content under node_modules — no findings (SKIP_DIRS)', () => {
    const dir = fixture('b07', {
      'node_modules/sample-pkg/index.js': [
        "const example = 'AKIAIOSFODNN7EXAMPLE';",
        "module.exports = { example };",
      ].join('\n') + '\n',
    });
    expect(getHighCriticalFindings(quickCredentialScan(dir))).toEqual([]);
  });

  it('b08: code-block in markdown docs — no findings on shape-only example', () => {
    const dir = fixture('b08', {
      'docs/setup.md': [
        '# Setup',
        '',
        '```bash',
        'export ANTHROPIC_API_KEY=<your-key>',
        'export OPENAI_API_KEY=<your-key>',
        '```',
      ].join('\n') + '\n',
    });
    expect(getHighCriticalFindings(quickCredentialScan(dir))).toEqual([]);
  });

  it('b09: template placeholder syntax — no findings', () => {
    const dir = fixture('b09', {
      'config.template.json': [
        '{',
        '  "anthropicKey": "{{ANTHROPIC_API_KEY}}",',
        '  "githubToken": "<GITHUB_TOKEN>"',
        '}',
      ].join('\n') + '\n',
    });
    expect(getHighCriticalFindings(quickCredentialScan(dir))).toEqual([]);
  });

  it('b10: regex literal showing key shape — no findings', () => {
    const dir = fixture('b10', {
      'patterns.js': [
        "// match Anthropic keys",
        "const ANTHROPIC_KEY_RE = /sk-ant-api\\d{2}-[A-Za-z0-9_-]{80,}/g;",
        "// match Google keys",
        "const GOOGLE_KEY_RE = /AIza[0-9A-Za-z_-]{35,}/g;",
      ].join('\n') + '\n',
    });
    expect(getHighCriticalFindings(quickCredentialScan(dir))).toEqual([]);
  });

  it('positive control: real-shaped Anthropic key SHOULD fire (sanity check on the gate)', () => {
    const dir = fixture('positive', {
      'app.js': "const apiKey = 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';\n",
    });
    const findings = getHighCriticalFindings(quickCredentialScan(dir));
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.findingId === 'CRED-001')).toBe(true);
  });
});
