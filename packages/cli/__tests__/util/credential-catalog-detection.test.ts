import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  collectCatalogMatches,
  catalogSeverityForCategory,
  BREADTH_DETECT_IDS,
  loadCanonicalPatterns,
  loadCanonicalAllowlist,
  quickCredentialScan,
  type CanonicalCredentialPattern,
  type IsKnownExample,
  type CredentialMatch,
} from '../../src/util/credential-patterns.js';

// Issue #130: protect/review/init detected only ~7 local patterns while `scan`
// finds ~57. The catalog breadth pass closes that gap via a fail-safe include
// list of strong-prefix patterns — additive, deduped against local matches,
// severity-by-category, FP-prone value-shape-only patterns excluded.

// Real-shaped (non-placeholder) values the LOCAL 7 patterns miss. Built by
// concatenation so GitHub Push Protection doesn't flag this test source.
const SLACK = ['xoxb-', '1234567890-1234567890-', 'aBcdEfGhIjKlMnOpQrStUvWx'].join('');
const STRIPE = ['sk_', 'live_', 'aBcdEfGhIjKlMnOpQrStUvWx'].join('');
const SENDGRID = ['SG', '.aBcdEfGhIjKlMnOpQrStUv.', 'aBcdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG'].join('');
const GITLAB = ['glpat-', 'aBcdEfGhIjKlMnOpQrSt'].join('');

let catalog: CanonicalCredentialPattern[];
let isKnownExample: IsKnownExample | null;

beforeAll(async () => {
  catalog = await loadCanonicalPatterns();
  isKnownExample = await loadCanonicalAllowlist();
});

const collect = (lines: string[], filePath: string, seen = new Set<string>()): CredentialMatch[] => {
  const matches: CredentialMatch[] = [];
  collectCatalogMatches(lines, filePath, catalog, isKnownExample, seen, matches);
  return matches;
};

describe('catalogSeverityForCategory', () => {
  it('maps account-takeover categories to critical', () => {
    for (const c of ['ai-ml', 'cloud', 'payment', 'auth']) {
      expect(catalogSeverityForCategory(c)).toBe('critical');
    }
  });
  it('maps repo/messaging/database to high and monitoring to medium', () => {
    for (const c of ['developer', 'communication', 'database']) {
      expect(catalogSeverityForCategory(c)).toBe('high');
    }
    expect(catalogSeverityForCategory('monitoring')).toBe('medium');
  });
  it('defaults an unknown/absent category to high (fail-safe, not silent)', () => {
    expect(catalogSeverityForCategory(undefined)).toBe('high');
    expect(catalogSeverityForCategory('something-new')).toBe('high');
  });
});

describe('BREADTH_DETECT_IDS — fail-safe include list', () => {
  it('every included id is a real catalog pattern (no typos / stale ids)', () => {
    const ids = new Set(catalog.map(p => p.id));
    for (const id of BREADTH_DETECT_IDS) {
      expect(ids.has(id), `BREADTH_DETECT_IDS has '${id}' not in the catalog`).toBe(true);
    }
  });
  it('excludes the FP-prone value-shape-only patterns (Phase 4.5)', () => {
    for (const id of ['supabase', 'telegram-bot', 'twilio', 'grafana', 'mongodb', 'postgres', 'mysql', 'redis']) {
      expect(BREADTH_DETECT_IDS.has(id), `'${id}' must NOT be in the breadth list`).toBe(false);
    }
  });
  it('excludes loose-floor short underscore prefixes (gsk_/r8_/hf_/fw_ match benign mixedCase identifiers)', () => {
    for (const id of ['groq', 'replicate', 'huggingface', 'fireworks']) {
      expect(BREADTH_DETECT_IDS.has(id), `'${id}' must NOT be in the breadth list`).toBe(false);
    }
    // Concrete proof: a benign mixedCase identifier with the hf_ prefix must not be flagged.
    const matches: CredentialMatch[] = [];
    collectCatalogMatches(['const hf_modelDownloadProgressBar = init();'], '/x/m.ts', catalog, isKnownExample, new Set(), matches);
    expect(matches).toHaveLength(0);
  });
  it('excludes patterns a local scanner already owns / non-migratable markers', () => {
    for (const id of ['aws-access', 'aws-secret', 'google', 'pem-private-key', 'gcp-service-account', 'anthropic']) {
      expect(BREADTH_DETECT_IDS.has(id), `'${id}' must NOT be in the breadth list`).toBe(false);
    }
  });

  it('excludes azure (name-gated, no capture group → m[0] is `Name=value`, would corrupt on migrate)', () => {
    // The azure regex matches `AccountKey=<base64>=` with no group 1, so m[0]
    // carries the name token; migrating it would vault the wrong value and break
    // the surrounding connection string. Must stay HMA-semantic only.
    expect(BREADTH_DETECT_IDS.has('azure')).toBe(false);
    const line = 'DefaultEndpointsProtocol=https;AccountName=foo;AccountKey=' + 'a'.repeat(43) + '=;EndpointSuffix=core';
    const matches: CredentialMatch[] = [];
    collectCatalogMatches([line], '/x/conn.ts', catalog, isKnownExample, new Set(), matches);
    expect(matches.some(m => m.findingId === 'CRED-CAT-azure')).toBe(false);
  });
});

describe('collectCatalogMatches', () => {
  it('loads a real catalog + allowlist (precondition)', () => {
    expect(catalog.length).toBeGreaterThan(20);
    expect(typeof isKnownExample).toBe('function');
  });

  it('detects catalog types the local 7 patterns miss, with category severity', () => {
    const matches = collect([
      `const slack = "${SLACK}";`,
      `const stripe = "${STRIPE}";`,
      `const sendgrid = "${SENDGRID}";`,
      `const gitlab = "${GITLAB}";`,
    ], '/x/config.js');

    const byValue = (v: string) => matches.find(m => m.value === v);
    expect(byValue(SLACK)).toMatchObject({ title: 'Slack Token', severity: 'high', findingId: 'CRED-CAT-slack', line: 1 });
    expect(byValue(STRIPE)).toMatchObject({ title: 'Stripe Live Key', severity: 'critical' });
    expect(byValue(SENDGRID)).toMatchObject({ title: 'SendGrid Key', severity: 'high', envVar: 'SENDGRID_API_KEY' });
    expect(byValue(GITLAB)).toMatchObject({ title: 'GitLab PAT', severity: 'high', line: 4 });
  });

  it('surfaces BOTH real secrets of the same pattern on one line (no first-match-only under-report)', () => {
    const g1 = ['glpat-', 'Aa1Bb2Cc3Dd4Ee5Ff6Gg'].join('');
    const g2 = ['glpat-', 'Zz9Yy8Xx7Ww6Vv5Uu4Tt'].join('');
    const matches = collect([`const a = "${g1}", b = "${g2}";`], '/x/c.js');
    expect(matches.map(m => m.value).sort()).toEqual([g1, g2].sort());
  });

  it('skips values already in `seen` (dedup vs local keeps the richer local label)', () => {
    const matches = collect([`const slack = "${SLACK}";`], '/x/config.js', new Set([`${SLACK}:/x/config.js`]));
    expect(matches).toHaveLength(0);
  });

  it('skips env-var references (process.env / ${...}) but flags the hardcoded literal', () => {
    const matches = collect([
      `const a = process.env.SLACK_TOKEN || "${SLACK}";`,
      `const b = process.env.SLACK_TOKEN;`,
    ], '/x/config.js');
    expect(matches.every(m => m.line === 1)).toBe(true);
  });

  it('suppresses placeholder / example values (allowlist via isKnownExample)', () => {
    const placeholder = ['xoxb-', '0000000000-0000000000-', 'EXAMPLEEXAMPLEEXAMPLE000'].join('');
    expect(collect([`const fake = "${placeholder}";`], '/x/config.js')).toHaveLength(0);
  });

  // Phase 4.5: value-shape-only patterns must NOT fire on benign content.
  // Tokens built by concatenation so GitHub Push Protection (which scans source
  // bytes) doesn't flag these deliberately-credential-shaped benign fixtures.
  it('does NOT false-positive on benign content (twilio SK+md5, telegram id:hash, bare conn string)', () => {
    const twilioShaped = ['SK', 'd41d8cd98f00b204e9800998ecf8427e'].join('');     // SK + an MD5 (etag)
    const telegramShaped = ['1623456789', ':', 'abcdefghijklmnopqrstuvwxyzABCDEFGHI'].join(''); // numeric:35
    const grafanaShaped = ['glc_', 'aBcdEfGhIjKlMnOpQrStUvWxYz012345'].join('');
    const benign = [
      `const etag = "${twilioShaped}";`,
      `const cacheKey = "${telegramShaped}";`,
      'const url = "postgres://localhost/mydb";',                     // credential-less conn string
      `const blob = "${grafanaShaped}";`,
    ];
    expect(collect(benign, '/x/util.js')).toHaveLength(0);
  });

  it('is a no-op when the allowlist failed to load (degrade, not crash)', () => {
    const matches: CredentialMatch[] = [];
    collectCatalogMatches([`const s = "${SLACK}";`], '/x/c.js', catalog, null, new Set(), matches);
    expect(matches).toHaveLength(0);
  });
});

describe('quickCredentialScan — catalog breadth integration', () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-cat-')); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  it('finds catalog types AND keeps the local label for an overlapping provider (no double-report)', async () => {
    const ANTHROPIC = ['sk-ant-api03-', 'aBcdEfGhIjKlMnOpQrStUvWx'].join('');
    fs.writeFileSync(path.join(tmpDir, 'config.js'), [
      `const anthropic = "${ANTHROPIC}";`, // local CRED-001
      `const slack = "${SLACK}";`,          // catalog
      `const stripe = "${STRIPE}";`,        // catalog
    ].join('\n'));

    const matches = await quickCredentialScan(tmpDir);

    // Anthropic appears exactly once, via the rich local pattern (not the catalog).
    const anth = matches.filter(m => m.value === ANTHROPIC);
    expect(anth).toHaveLength(1);
    expect(anth[0].findingId).toBe('CRED-001');

    // Catalog breadth: slack + stripe are now detected.
    expect(matches.find(m => m.value === SLACK)?.findingId).toBe('CRED-CAT-slack');
    expect(matches.find(m => m.value === STRIPE)?.findingId).toBe('CRED-CAT-stripe');
  });
});
