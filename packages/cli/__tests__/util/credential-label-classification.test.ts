import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  classifyCredentialValue,
  refineCredentialLabel,
  loadCanonicalPatterns,
  quickCredentialScan,
  type CanonicalCredentialPattern,
} from '../../src/util/credential-patterns.js';

// Regression for the `opena2a protect` cosmetic bug: the local CRED-002 pattern
// matches `sk-(?!ant-)…` and labelled EVERY non-Anthropic `sk-` token
// "OpenAI API Key". The label is now routed through the canonical
// `@opena2a/credential-patterns` catalog so anthropic / openai-* / openrouter /
// stripe `sk_` are distinguished. See session-protect-credential-label-shared-catalog.

// Synthetic, non-real key shapes (length-padded to satisfy the catalog regexes).
const ANTHROPIC_KEY = 'sk-ant-api03-' + 'a'.repeat(80);
const OPENAI_PROJ_KEY = 'sk-proj-' + 'a'.repeat(40);
const OPENAI_LEGACY_KEY = 'sk-' + 'a'.repeat(48);
const OPENROUTER_KEY = 'sk-or-v1-' + 'a'.repeat(48);
const STRIPE_LIVE_KEY = 'sk_live_' + 'a'.repeat(24);
const STRIPE_TEST_KEY = 'sk_test_' + 'a'.repeat(24);

let catalog: CanonicalCredentialPattern[];

beforeAll(async () => {
  catalog = await loadCanonicalPatterns();
});

describe('classifyCredentialValue', () => {
  it('loads a non-empty canonical catalog', () => {
    expect(catalog.length).toBeGreaterThan(0);
  });

  it('labels an Anthropic key as Anthropic, not OpenAI', async () => {
    expect(classifyCredentialValue(ANTHROPIC_KEY, catalog)).toEqual({
      title: 'Anthropic API Key',
      envVarPrefix: 'ANTHROPIC_API_KEY',
    });
  });

  it('labels an OpenAI project key as OpenAI', async () => {
    expect(classifyCredentialValue(OPENAI_PROJ_KEY, catalog)).toEqual({
      title: 'OpenAI Project Key',
      envVarPrefix: 'OPENAI_API_KEY',
    });
  });

  it('labels a legacy OpenAI key as OpenAI', async () => {
    expect(classifyCredentialValue(OPENAI_LEGACY_KEY, catalog)).toEqual({
      title: 'OpenAI Legacy Key',
      envVarPrefix: 'OPENAI_API_KEY',
    });
  });

  it('labels an OpenRouter key as OpenRouter (not OpenAI)', async () => {
    expect(classifyCredentialValue(OPENROUTER_KEY, catalog)).toEqual({
      title: 'OpenRouter API Key',
      envVarPrefix: 'OPENROUTER_API_KEY',
    });
  });

  it('labels a Stripe live key as Stripe (not OpenAI)', async () => {
    expect(classifyCredentialValue(STRIPE_LIVE_KEY, catalog)).toEqual({
      title: 'Stripe Live Key',
      envVarPrefix: 'STRIPE_SECRET_KEY',
    });
  });

  it('labels a Stripe test key as Stripe (not OpenAI)', async () => {
    expect(classifyCredentialValue(STRIPE_TEST_KEY, catalog)).toEqual({
      title: 'Stripe Test Key',
      envVarPrefix: 'STRIPE_SECRET_KEY',
    });
  });

  it('returns null for an unrecognised value', () => {
    expect(classifyCredentialValue('not-a-credential-12345', catalog)).toBeNull();
  });
});

describe('refineCredentialLabel', () => {
  const fallback = { title: 'OpenAI API Key', envVarPrefix: 'OPENAI_API_KEY' };

  it('refines the CRED-002 catch-all to the precise provider, with matching prose', () => {
    const refined = refineCredentialLabel('CRED-002', OPENROUTER_KEY, fallback, catalog);
    expect(refined.title).toBe('OpenRouter API Key');
    expect(refined.envVarPrefix).toBe('OPENROUTER_API_KEY');
    // Prose is provider-neutral and must NOT name a different provider than the title.
    expect(refined.explanation).toContain('OpenRouter API Key');
    expect(refined.explanation).not.toMatch(/OpenAI/);
    expect(refined.businessImpact).not.toMatch(/OpenAI/);
  });

  it('refines a CRED-004 generic assignment value (Stripe) to the precise provider, with matching prose', () => {
    const generic = { title: 'Generic API Key in Assignment', envVarPrefix: 'API_KEY' };
    const refined = refineCredentialLabel('CRED-004', STRIPE_LIVE_KEY, generic, catalog);
    expect(refined.title).toBe('Stripe Live Key');
    expect(refined.envVarPrefix).toBe('STRIPE_SECRET_KEY');
    // The generic "Generic API key …" prose must be replaced so it names Stripe.
    expect(refined.explanation).toContain('Stripe Live Key');
    expect(refined.explanation).not.toMatch(/Generic API key/i);
  });

  it('does not name a provider in the prose that contradicts the refined title (regression P2-1)', () => {
    // P2-1 from the 0.10.8 release test: refined Type "OpenRouter API Key" shipped
    // with "Why: OpenAI API key … grants full OpenAI API access" — a self-contradiction.
    // For every refinable catch-all whose value resolves to a DIFFERENT provider,
    // the refined prose must reference the refined title and no other vendor.
    const cases: Array<{ id: string; value: string; expectTitle: string; forbid: RegExp }> = [
      { id: 'CRED-002', value: OPENROUTER_KEY, expectTitle: 'OpenRouter API Key', forbid: /OpenAI/ },
      { id: 'CRED-004', value: STRIPE_LIVE_KEY, expectTitle: 'Stripe Live Key', forbid: /OpenAI|Generic API key/i },
      { id: 'CRED-004', value: STRIPE_TEST_KEY, expectTitle: 'Stripe Test Key', forbid: /OpenAI|Generic API key/i },
    ];
    for (const c of cases) {
      const refined = refineCredentialLabel(c.id, c.value, { title: 'OpenAI API Key', envVarPrefix: 'OPENAI_API_KEY' }, catalog);
      expect(refined.title).toBe(c.expectTitle);
      expect(refined.explanation).toBeDefined();
      expect(refined.explanation).toContain(c.expectTitle);
      expect(refined.explanation).not.toMatch(c.forbid);
      expect(refined.businessImpact).not.toMatch(/OpenAI/);
    }
  });

  it('leaves prose absent (caller keeps local copy) when the title is unchanged', () => {
    // CRED-002 fallback already titled "OpenAI API Key"; a value the catalog also
    // calls "OpenAI API Key" produces no title change, so no prose override.
    const same = refineCredentialLabel('CRED-002', 'sk-test-short', fallback, catalog);
    expect(same).toEqual(fallback);
    expect((same as { explanation?: string }).explanation).toBeUndefined();
  });

  it('keeps the local label for non-refinable specific patterns', () => {
    // DRIFT-002 carries deliberate "(Bedrock drift risk)" framing the catalog lacks.
    const aws = { title: 'AWS Access Key (Bedrock drift risk)', envVarPrefix: 'AWS_ACCESS_KEY_ID' };
    expect(refineCredentialLabel('DRIFT-002', 'AKIA' + 'A'.repeat(16), aws, catalog)).toEqual(aws);
  });

  it('keeps the fallback when the value matches nothing in the catalog', () => {
    expect(refineCredentialLabel('CRED-002', 'sk-test-short', fallback, catalog)).toEqual(fallback);
  });
});

describe('quickCredentialScan label routing (integration)', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-label-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function write(rel: string, body: string): void {
    const abs = path.join(tmpDir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, body);
  }

  it('labels a hardcoded Anthropic key as Anthropic, not OpenAI', async () => {
    write('config.js', `const apiKey = "${ANTHROPIC_KEY}";`);
    const matches = await quickCredentialScan(tmpDir);
    const m = matches.find(x => x.value === ANTHROPIC_KEY);
    expect(m).toBeDefined();
    expect(m!.title).toBe('Anthropic API Key');
    expect(m!.envVar).toBe('ANTHROPIC_API_KEY');
  });

  it('labels a hardcoded Stripe key in an assignment as Stripe, not OpenAI', async () => {
    write('billing.js', `const apiKey = "${STRIPE_LIVE_KEY}";`);
    const matches = await quickCredentialScan(tmpDir);
    const m = matches.find(x => x.value === STRIPE_LIVE_KEY);
    expect(m).toBeDefined();
    expect(m!.title).toBe('Stripe Live Key');
    expect(m!.envVar).toBe('STRIPE_SECRET_KEY');
  });

  it('labels a hardcoded OpenRouter key as OpenRouter, not OpenAI', async () => {
    write('llm.js', `const apiKey = "${OPENROUTER_KEY}";`);
    const matches = await quickCredentialScan(tmpDir);
    const m = matches.find(x => x.value === OPENROUTER_KEY);
    expect(m).toBeDefined();
    expect(m!.title).toBe('OpenRouter API Key');
    expect(m!.envVar).toBe('OPENROUTER_API_KEY');
  });

  it('still labels a real OpenAI key as OpenAI', async () => {
    write('openai.js', `const apiKey = "${OPENAI_PROJ_KEY}";`);
    const matches = await quickCredentialScan(tmpDir);
    const m = matches.find(x => x.value === OPENAI_PROJ_KEY);
    expect(m).toBeDefined();
    expect(m!.title).toMatch(/OpenAI/);
    expect(m!.envVar).toBe('OPENAI_API_KEY');
  });

  it('renders explanation/impact prose that matches the refined title (regression P2-1)', async () => {
    // The rendered "Why:"/"Impact:" come from match.explanation/businessImpact.
    // An OpenRouter key must not carry "OpenAI" rationale.
    write('llm.js', `const apiKey = "${OPENROUTER_KEY}";`);
    const matches = await quickCredentialScan(tmpDir);
    const m = matches.find(x => x.value === OPENROUTER_KEY);
    expect(m).toBeDefined();
    expect(m!.title).toBe('OpenRouter API Key');
    expect(m!.explanation).toBeDefined();
    expect(m!.explanation).toContain('OpenRouter API Key');
    expect(m!.explanation).not.toMatch(/OpenAI/);
    expect(m!.businessImpact).not.toMatch(/OpenAI/);
  });

  it('keeps rich local Anthropic prose (no refinement → no neutralization)', async () => {
    write('anthropic.js', `const apiKey = "${ANTHROPIC_KEY}";`);
    const matches = await quickCredentialScan(tmpDir);
    const m = matches.find(x => x.value === ANTHROPIC_KEY);
    expect(m).toBeDefined();
    // CRED-001 is not refinable; its specific copy is preserved verbatim.
    expect(m!.explanation).toContain('Claude models');
  });
});
