import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scanTemplateEnvLeaks } from '../../src/util/credential-patterns.js';
import { calculateSecurityScore } from '../../src/util/scoring.js';
import { init } from '../../src/commands/init.js';

// Regression for opena2a#227: `init` scored the buggy corpus tier
// (repo/buggy/leaky-env-example) identically to benign because it could not see
// the credential-shaped values committed inside `.env.example`. The migration
// scanner (quickCredentialScan/protect) skips template env files by design;
// `scanTemplateEnvLeaks` restores the POSTURE signal for `init` without
// rewiring the migration path. HMA `secure` flags the same file (CONFIG-004),
// and the shared corpus manifest ratifies it as critical.

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tmpl-env-leak-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function write(rel: string, body: string): void {
  const abs = path.join(tmpDir, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, body);
}

// Credential-SHAPED but synthetic test values (high entropy so the low-entropy
// filter does not drop them). Every prefix is split from its body via `+` so no
// contiguous `AKIA…`/`ghp_…`/`sk-proj-…`/`sk_live_…` secret literal ever appears
// in this committed source — GitHub push-protection secret scanning matches on
// the file bytes, and these are non-secrets. The concatenation reconstitutes the
// full value at runtime for the scanner under test.
const AWS_SHAPED = 'AKI' + 'AZ7QW3E9RT2YU8IOP';                     // AKIA + 16, entropy > 6
const GH_SHAPED = 'ghp' + '_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';  // ghp_ + 36, entropy > 6
const OPENAI_SHAPED = 'sk-' + 'proj-Ab3xK9mZ1qWvT7nR5uP2eL8dF4gH6jS0cX'; // sk-proj- + alnum
const STRIPE_SHAPED = 'sk_' + 'live_51Ab3xK9mZ1qWvT7nR5uP2eL8dF4gH6jS0cXbY'; // sk_live_ + alnum

function captureStdout(fn: () => Promise<number>): Promise<{ exitCode: number; output: string }> {
  const chunks: string[] = [];
  const orig = process.stdout.write.bind(process.stdout);
  (process.stdout.write as unknown) = (s: string) => { chunks.push(s.toString()); return true; };
  // `finally` guarantees stdout is restored even if `fn()` rejects, so a
  // throwing case can never leave stdout hijacked for the next test.
  return fn()
    .then((exitCode) => ({ exitCode, output: chunks.join('') }))
    .finally(() => { (process.stdout.write as unknown) = orig; });
}

describe('scanTemplateEnvLeaks: fires on real-shaped values in template env files', () => {
  it('flags an AWS access key + GitHub token committed in .env.example', () => {
    write('.env.example',
      `AWS_ACCESS_KEY_ID=${AWS_SHAPED}\n` +
      `GITHUB_TOKEN=${GH_SHAPED}\n`);
    const leaks = scanTemplateEnvLeaks(tmpDir);
    expect(leaks.length).toBe(2);
    expect(leaks.map(l => l.title).sort()).toEqual(['AWS Access Key', 'GitHub Token']);
    // Clean provider label — no drift-risk parenthetical leaks into the title.
    expect(leaks.every(l => !l.title.includes('('))).toBe(true);
    expect(leaks.every(l => path.basename(l.filePath) === '.env.example')).toBe(true);
  });

  it('covers all four template names (.env.example/.sample/.template/.dist)', () => {
    for (const name of ['.env.example', '.env.sample', '.env.template', '.env.dist']) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      fs.mkdirSync(tmpDir, { recursive: true });
      write(name, `AWS_ACCESS_KEY_ID=${AWS_SHAPED}\n`);
      expect(scanTemplateEnvLeaks(tmpDir).length, name).toBe(1);
    }
  });

  it('finds a leak in a nested (non-skipped) directory', () => {
    write('config/deploy/.env.example', `AWS_ACCESS_KEY_ID=${AWS_SHAPED}\n`);
    expect(scanTemplateEnvLeaks(tmpDir).length).toBe(1);
  });

  // Cross-command consistency (opena2a#227 Phase 4.5): `init` must agree in
  // direction with `hackmyagent secure` (CONFIG-004), which flags OpenAI /
  // Stripe env-file leaks. The alnum-only patterns match a real key.
  it('flags a real-shaped OpenAI project key (sk-proj-…) — agrees with HMA CONFIG-004', () => {
    write('.env.example', `OPENAI_API_KEY=${OPENAI_SHAPED}\n`);
    const leaks = scanTemplateEnvLeaks(tmpDir);
    expect(leaks.length).toBe(1);
    expect(leaks[0].title).toBe('OpenAI API Key');
  });

  it('flags a real-shaped Stripe live secret (sk_live_…)', () => {
    write('.env.example', `STRIPE_SECRET_KEY=${STRIPE_SHAPED}\n`);
    const leaks = scanTemplateEnvLeaks(tmpDir);
    expect(leaks.length).toBe(1);
    expect(leaks[0].title).toBe('Stripe Secret Key');
  });
});

describe('scanTemplateEnvLeaks: high-precision — no false positives on well-formed templates', () => {
  it('does NOT fire on empty placeholder assignments (the well-formed template)', () => {
    write('.env.example',
      'ANTHROPIC_API_KEY=\n' +
      'OPENAI_API_KEY=\n' +
      'STRIPE_LIVE_KEY=\n' +
      'DATABASE_URL=postgres://user:password@localhost:5432/mydb\n');
    expect(scanTemplateEnvLeaks(tmpDir)).toEqual([]);
  });

  it('does NOT fire on textual placeholders (your-key-here style)', () => {
    write('.env.example',
      'AWS_ACCESS_KEY_ID=your-access-key-id\n' +
      'GITHUB_TOKEN=ghp_your_token_here\n' +
      'GOOGLE_API_KEY=your-google-api-key\n');
    expect(scanTemplateEnvLeaks(tmpDir)).toEqual([]);
  });

  it('does NOT fire on a hyphenated OpenAI placeholder (alnum-only pattern rejects hyphens)', () => {
    write('.env.example', 'OPENAI_API_KEY=sk-your-openai-api-key-goes-here\n');
    expect(scanTemplateEnvLeaks(tmpDir)).toEqual([]);
  });

  it('does NOT fire on documented AWS/Google example keys (EXAMPLE marker — empower-never-shame)', () => {
    // AWS's own canonical docs example + a Google key literally containing EXAMPLE.
    // HMA CONFIG-004 over-fires on these; init suppresses them (no non-secret to rotate).
    write('.env.example',
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n' +
      'GOOGLE_API_KEY=AIzaSyD-EXAMPLE1234567890abcdefghijklmno\n');
    expect(scanTemplateEnvLeaks(tmpDir)).toEqual([]);
  });

  it('does NOT fire on low-entropy filler (ghp_xxxx… / AKIAAAAA…)', () => {
    write('.env.example',
      'GITHUB_TOKEN=ghp_' + 'x'.repeat(36) + '\n' +
      'AWS_ACCESS_KEY_ID=AKIA' + 'A'.repeat(16) + '\n');
    expect(scanTemplateEnvLeaks(tmpDir)).toEqual([]);
  });

  it('does NOT scan a live .env file (that is the migration scanner\'s surface, not this posture check)', () => {
    write('.env', `AWS_ACCESS_KEY_ID=${AWS_SHAPED}\n`);
    expect(scanTemplateEnvLeaks(tmpDir)).toEqual([]);
  });

  it('does NOT descend into node_modules / .git', () => {
    write('node_modules/pkg/.env.example', `AWS_ACCESS_KEY_ID=${AWS_SHAPED}\n`);
    write('.git/.env.example', `AWS_ACCESS_KEY_ID=${AWS_SHAPED}\n`);
    expect(scanTemplateEnvLeaks(tmpDir)).toEqual([]);
  });
});

describe('calculateSecurityScore: templateEnvLeak scores one critical-equivalent', () => {
  const cleanChecks = [
    { label: 'Credential scan', status: 'pass' as const, detail: 'no findings' },
    { label: '.gitignore', status: 'pass' as const, detail: 'present' },
    { label: '.env protection', status: 'pass' as const, detail: 'in .gitignore' },
    { label: 'Lock file', status: 'pass' as const, detail: 'package-lock.json' },
    { label: 'Security config', status: 'pass' as const, detail: '.opena2a.yaml' },
  ];

  it('deducts 20 (one critical-equivalent) and suppresses the clean-project bonus', () => {
    const clean = calculateSecurityScore({}, cleanChecks).score;
    const leaked = calculateSecurityScore({}, cleanChecks, undefined, { templateEnvLeak: true }).score;
    // clean is 100 + 5 bonus -> clamped to 100; leaked loses the +5 bonus
    // (hasHighImpact now true) AND takes the -20 credential-equivalent.
    // cleanChecks has no config deductions, so leaked = 100 - 20 = 80.
    expect(clean).toBe(100);
    expect(leaked).toBe(80);
    expect(leaked).toBeLessThan(clean);
  });

  it('surfaces the leak in the credentials breakdown detail', () => {
    const { breakdown } = calculateSecurityScore({}, cleanChecks, undefined, { templateEnvLeak: true });
    expect(breakdown.credentials.deduction).toBe(20);
    expect(breakdown.credentials.detail).toContain('template env file');
  });
});

describe('init end-to-end: leaky template scores below a clean repo (opena2a#227 monotonicity)', () => {
  it('emits ENV-EXAMPLE-LEAK critical and scores strictly below an otherwise-identical clean repo', async () => {
    // Clean repo: lock file + security config + gitignore, no template leak.
    const cleanDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clean-'));
    // Buggy repo: identical, plus a leaky .env.example.
    const buggyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'buggy-'));
    try {
      for (const d of [cleanDir, buggyDir]) {
        fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name: 'r', version: '1.0.0' }));
        fs.writeFileSync(path.join(d, '.gitignore'), '.env\nnode_modules\n');
        fs.writeFileSync(path.join(d, 'package-lock.json'), '{}');
      }
      fs.writeFileSync(path.join(buggyDir, '.env.example'),
        `AWS_ACCESS_KEY_ID=${AWS_SHAPED}\nGITHUB_TOKEN=${GH_SHAPED}\n`);

      const clean = JSON.parse((await captureStdout(() => init({ targetDir: cleanDir, format: 'json' }))).output);
      const buggy = JSON.parse((await captureStdout(() => init({ targetDir: buggyDir, format: 'json' }))).output);

      const leak = buggy.findings.find((f: { findingId: string }) => f.findingId === 'ENV-EXAMPLE-LEAK');
      expect(leak).toBeDefined();
      expect(leak.severity).toBe('critical');
      expect(leak.locations.length).toBe(2);

      expect(clean.findings.some((f: { findingId: string }) => f.findingId === 'ENV-EXAMPLE-LEAK')).toBe(false);
      expect(buggy.securityScore).toBeLessThan(clean.securityScore);

      // The leak has a non-dead-end remediation: verify reveals the line, a
      // Recommendations action carries the fix, and it does NOT point at protect.
      expect(leak.verify).toMatch(/^sed -n '\d+p'/);
      const action = buggy.actions.find((a: { command: string }) => /grep -nE/.test(a.command));
      expect(action).toBeDefined();
    } finally {
      fs.rmSync(cleanDir, { recursive: true, force: true });
      fs.rmSync(buggyDir, { recursive: true, force: true });
    }
  });
});
