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

  it('refines the CRED-002 catch-all to the precise provider', () => {
    expect(refineCredentialLabel('CRED-002', OPENROUTER_KEY, fallback, catalog)).toEqual({
      title: 'OpenRouter API Key',
      envVarPrefix: 'OPENROUTER_API_KEY',
    });
  });

  it('refines a CRED-004 generic assignment value (Stripe) to the precise provider', () => {
    const generic = { title: 'Generic API Key in Assignment', envVarPrefix: 'API_KEY' };
    expect(refineCredentialLabel('CRED-004', STRIPE_LIVE_KEY, generic, catalog)).toEqual({
      title: 'Stripe Live Key',
      envVarPrefix: 'STRIPE_SECRET_KEY',
    });
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
});
