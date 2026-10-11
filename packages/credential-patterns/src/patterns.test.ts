import { describe, it, expect } from 'vitest';
import { CONFIG_FILES, CREDENTIAL_PATTERNS, CREDENTIAL_PREFIX_QUICK_CHECK } from './patterns.js';
import { findRealMatch } from './match.js';

/**
 * Test data for each pattern: valid strings that MUST match, invalid strings that MUST NOT.
 *
 * Strings here are synthetic (mostly `'a'.repeat(n)` shape fixtures) — they exercise
 * regex shape, not real credentials. Tokens that look credential-shaped are built
 * dynamically to avoid triggering GitHub Push Protection on this file itself.
 */
// Build test tokens dynamically to avoid triggering GitHub Push Protection
const slackTestToken = ['xox', 'b-1234567890-1234567890-', 'abcdefghijklmnopqrstuvwx'].join('');
const slackUserTestToken = ['xox', 'p-123456789012-123456789012-1234567890123-', '0123456789abcdef'.repeat(2)].join('');
const discordBotToken = ['MTIzNDU2Nzg5MDEyMzQ1Njc4OQ', '.GabcDE.', 'abcdefghijklmnopqrstuvwxyz01234'].join('');
const anthropicTestKey = ['sk-ant-api03-', 'abc123def456abc123def456abc123'].join('');
const awsAccessTestKey = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const awsStsTestKey = ['ASIA', 'IOSFODNN7EXAMPLE'].join('');
const githubPatTestToken = ['ghp_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('');
const mongodbSrvTestUri = ['mongodb+srv://', 'user:pass', '@cluster.mongodb.net/db'].join('');
const googleTestKey = ['AIza', 'SyB-abc_def123456789012345678901234'].join('');

const PATTERN_TEST_CASES: Record<string, { valid: string[]; invalid: string[] }> = {
  // AI/ML
  'anthropic': {
    valid: [anthropicTestKey],
    invalid: ['sk-ant-wrong', 'sk-ant-api-tooshort'],
  },
  'openai-proj': {
    valid: ['sk-proj-Qm50BIe8JjiH5tDZHMIuf7HsH6C91Ye'],
    invalid: ['sk-proj-short', 'sk-proj-'],
  },
  'openrouter': {
    valid: ['sk-or-v1-' + 'a'.repeat(48)],
    invalid: ['sk-or-v1-short', 'sk-or-v2-' + 'a'.repeat(48)],
  },
  'openai-legacy': {
    valid: ['sk-' + 'a'.repeat(48)],
    invalid: ['sk-' + 'a'.repeat(10), 'sk-short'],
  },
  'groq': {
    valid: ['gsk_abc123def456abc123def456'],
    invalid: ['gsk_short', 'gsk_'],
  },
  'replicate': {
    valid: ['r8_abcdef1234567890abcdef'],
    invalid: ['r8_short', 'r8_'],
  },
  'huggingface': {
    valid: ['hf_abcdef1234567890abcdef'],
    invalid: ['hf_short', 'hf_'],
  },
  'perplexity': {
    valid: ['pplx-' + 'a'.repeat(48)],
    invalid: ['pplx-short', 'pplx-' + 'a'.repeat(10)],
  },
  'fireworks': {
    valid: ['fw_abcdef1234567890abcdef'],
    invalid: ['fw_short', 'fw_'],
  },

  // Cloud
  'aws-access': {
    valid: [awsAccessTestKey],
    invalid: ['AKIA123', 'BKIAIOSFODNN7EXAMPLE'],
  },
  'aws-sts': {
    valid: [awsStsTestKey],
    invalid: ['ASIA123', 'BSIAIOSFODNN7EXAMPLE'],
  },
  'aws-secret': {
    // Name-gated: a 40-char value matches only when an `aws…secret…key` /
    // `secret_access_key` name precedes it (lookbehind). match[0] is the value.
    valid: [
      'AWS_SECRET_ACCESS_KEY=' + 'a'.repeat(40),
      'aws_secret_access_key = "' + 'b'.repeat(40) + '"',
      'secretAccessKey: "' + 'c'.repeat(40) + '"',          // JS SDK, no "aws"
      'secret_access_key = "' + 'd'.repeat(40) + '"',        // Terraform
    ],
    invalid: [
      'e'.repeat(40),                                        // bare 40-char, no name
      'aws_secret_access_key = "tooShort"',                  // value not 40 chars
      'aws secretsmanager arn: ' + 'f'.repeat(40),           // no "key" token
      'session_secret = "' + 'g'.repeat(40) + '"',           // no "aws", not the full phrase
    ],
  },
  'gcp-service-account': {
    valid: ['"type": "service_account"', '"type":"service_account"'],
    invalid: ['"type": "user_account"', '"type":"oauth"'],
  },
  'digitalocean': {
    valid: ['dop_v1_' + 'a'.repeat(64)],
    invalid: ['dop_v1_short', 'dop_v2_' + 'a'.repeat(64)],
  },
  'heroku': {
    valid: ['HRKU-' + 'a'.repeat(30)],
    invalid: ['HRKU-short', 'HRKU-' + 'a'.repeat(5)],
  },
  'fly-io': {
    valid: ['fo1_' + 'a'.repeat(20)],
    invalid: ['fo1_short', 'fo1_'],
  },
  'netlify': {
    valid: ['nfp_' + 'a'.repeat(40)],
    invalid: ['nfp_short', 'nfp_' + 'a'.repeat(5)],
  },
  'azure': {
    valid: [
      'AccountKey=' + 'a'.repeat(43) + '=',
      'SharedAccessKey = ' + 'B'.repeat(43) + '=',
      'AccountKey=' + 'a'.repeat(86) + '==',                 // 512-bit Storage account key
    ],
    invalid: [
      'AccountKey=short',
      'RandomKey=' + 'a'.repeat(43) + '=',
      'sha512-' + 'a'.repeat(86) + '==',                     // integrity value, no key name
    ],
  },
  'supabase': {
    valid: ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + 'a'.repeat(50)],
    invalid: ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.short'],
  },

  // Communication
  'slack': {
    valid: [slackTestToken, slackUserTestToken],
    invalid: ['xoxb-short', 'xoxz-1234567890-1234567890-abcdefghijklmnopqrstuvwx'],
  },
  'slack-webhook': {
    valid: ['hooks.slack.com/services/T01234567/B01234567/abcdefghijklmnopqrstuvwx'],
    invalid: ['hooks.slack.com/services/T012/B012/abc', 'hooks.slack.com/other'],
  },
  'slack-app': {
    valid: ['xapp-1-A01234567-12345-abcdef0123456789'],
    invalid: ['xapp-nope'],
  },
  'telegram-bot': {
    valid: ['123456789:ABCDefgh_ijklmnopQRSTuvwxyz012345678'],
    invalid: ['12345:short', '1234567:AB'],
  },
  'discord-bot': {
    valid: [discordBotToken],
    invalid: ['short.ab.cd', 'Xshort.abcdef.short'],
  },
  'discord-webhook': {
    valid: ['discord.com/api/webhooks/123456789/abcdef_GHIJKL-mnop'],
    invalid: ['discord.com/api/other/123', 'discord.com/webhooks/123/abc'],
  },
  'twilio': {
    valid: ['SK' + 'a'.repeat(32)],
    invalid: ['SK' + 'a'.repeat(10), 'SKshort'],
  },
  'sendgrid': {
    valid: ['SG.' + 'a'.repeat(22) + '.' + 'b'.repeat(43)],
    invalid: ['SG.short.short', 'SG.abc'],
  },

  // Developer
  'github-pat': {
    valid: [githubPatTestToken],
    invalid: ['ghp_short', 'ghp_'],
  },
  'github-fine': {
    valid: ['github_pat_' + 'a'.repeat(22) + '_' + 'b'.repeat(59)],
    invalid: ['github_pat_short_short', 'github_pat_' + 'a'.repeat(5) + '_' + 'b'.repeat(5)],
  },
  'github-oauth': {
    valid: ['gho_' + 'a'.repeat(36)],
    invalid: ['gho_short', 'gho_'],
  },
  'github-app': {
    valid: ['ghs_' + 'a'.repeat(36)],
    invalid: ['ghs_short', 'ghs_'],
  },
  'github-user-to-server': {
    valid: ['ghu_' + 'a'.repeat(36)],
    invalid: ['ghu_short', 'ghu_', 'ghu_' + 'a'.repeat(35)],
  },
  'github-refresh': {
    valid: ['ghr_' + 'a'.repeat(36)],
    invalid: ['ghr_short', 'ghr_'],
  },
  'gitlab': {
    valid: ['glpat-' + 'a'.repeat(20)],
    invalid: ['glpat-short', 'glpat-'],
  },
  'gitlab-pipeline': {
    valid: ['glptt-' + 'a'.repeat(40)],
    invalid: ['glptt-short', 'glptt-'],
  },
  'gitlab-runner': {
    valid: ['GR1348941' + 'a'.repeat(20)],
    invalid: ['GR1348941short', 'GR1348941'],
  },
  'npm': {
    valid: ['npm_' + 'a'.repeat(36)],
    invalid: ['npm_short', 'npm_'],
  },
  'pypi': {
    valid: ['pypi-' + 'a'.repeat(50)],
    invalid: ['pypi-short', 'pypi-' + 'a'.repeat(10)],
  },
  'dockerhub': {
    valid: ['dckr_pat_' + 'a'.repeat(20)],
    invalid: ['dckr_pat_short', 'dckr_pat_'],
  },
  'bitbucket': {
    valid: ['ATBB' + 'a'.repeat(32)],
    invalid: ['ATBB' + 'a'.repeat(5), 'ATBBshort'],
  },

  // Payment
  'stripe-test': {
    valid: ['sk_test_' + 'a'.repeat(24)],
    invalid: ['sk_test_short', 'sk_test_'],
  },
  'stripe-restricted': {
    valid: ['rk_live_' + 'a'.repeat(24)],
    invalid: ['rk_live_short', 'rk_live_'],
  },
  'stripe': {
    valid: ['sk_live_' + 'a'.repeat(24)],
    invalid: ['sk_live_short', 'sk_live_'],
  },
  'stripe-webhook': {
    valid: ['whsec_' + 'a'.repeat(32)],
    invalid: ['whsec_short', 'whsec_'],
  },
  'square': {
    valid: ['sq0csp-' + 'a'.repeat(22)],
    invalid: ['sq0csp-short', 'sq0CSP-' + 'a'.repeat(22)],
  },
  'square-access-token': {
    valid: ['EAAA' + 'a'.repeat(60), '"EAAA' + 'a'.repeat(60) + '"'],
    invalid: [
      'EAAA' + 'a'.repeat(59),
      'EAAA' + 'a'.repeat(61),                               // part of a longer run
      'b' + 'EAAA' + 'a'.repeat(60),                         // inside a base64 run
    ],
  },

  // Database — connection strings flag only when a secret is embedded:
  // a userinfo password (or, for redis, any single userinfo token — pre-ACL
  // Redis has no usernames) or a password=/pwd=/sslpassword= query param.
  // Credential-free URIs are topology, not exposures, and matches must not
  // cross JSON string boundaries on minified content.
  'mongodb': {
    valid: [
      mongodbSrvTestUri,
      'mongodb://admin:hunter2@mongo1:27017,mongo2:27017/db',
    ],
    invalid: ['mongodb://lo', 'mongo+srv://x', 'mongodb+srv://cluster.mongodb.net/db'],
  },
  'postgres': {
    valid: [
      'postgres://user:pass@localhost:5432/mydb',
      'postgresql://localhost:5432/mydb?password=hunter2',
      'postgresql://localhost:5432/mydb?Password=hunter2',
      'postgresql://host:5432/db?sslmode=verify-full&sslpassword=keypass',
      'postgres://user:p%40ssw0rd@host/db',
      'postgres://u:p@[::1]:5432/db',
      'postgres://u:p@h1:5432,h2:5432/db',
      'postgresql:///db?host=/cloudsql/proj:region:inst&password=y',
    ],
    invalid: [
      'postgres://s',
      'pg://user:pass@host/db',
      'postgres://localhost:5432/mydb',
      'postgresql://localhost:5432/mydb',
      '{"conn":"postgres://localhost:5432/db","email":"a@b.com"}',
      '{"x":"postgres://","y":"a:b@c"}',
      '{"a":"postgres://localhost/db","note":"?password=hunter2"}',
      'DATABASE_URL: postgres://app:${POSTGRES_PASSWORD}@db:5432/app',
      'db_url: postgres://app:$DB_PASSWORD@db:5432/app',
      'notes: postgres://reporting:5432/warehouse|oncall@corp.io',
      'DATABASE_URL=postgres://localhost:5432/db;EMAIL=admin@example.com',
      'postgresql://h/db?password=${DB_PASS}',
    ],
  },
  'mysql': {
    valid: ['mysql://user:pass@localhost:3306/mydb'],
    invalid: ['mysql://sh', 'msql://user:pass@host/db', 'mysql://localhost:3306/mydb'],
  },
  'redis': {
    valid: [
      'redis://user:pass@localhost:6379/0',
      'rediss://:secure@host:6379',
      'rediss://secure@host:6379',
      'redis://mysecretpassword@redis-host:6379',
      'redis://:s3cretRedisPw99Xy@${REDIS_HOST}:6379/0',
    ],
    invalid: [
      'redis://sh',
      'rds://host:6379',
      'redis://localhost:6379',
      '{"cache":"redis://localhost:6379","owner":"ops@corp.io"}',
      'redis://default@cache.prod.internal:6379',
    ],
  },

  // Auth & Crypto
  'google': {
    valid: [googleTestKey],
    invalid: ['AIzaShort', 'BIzaSyBabc1234567890123456789012345'],
  },
  'google-oauth': {
    valid: ['ya29.' + 'a'.repeat(50)],
    invalid: ['ya29.' + 'a'.repeat(10), 'ya29.short'],
  },
  'pem-private-key': {
    valid: [
      '-----BEGIN PRIVATE KEY-----',
      '-----BEGIN RSA PRIVATE KEY-----',
      '-----BEGIN EC PRIVATE KEY-----',
      '-----BEGIN OPENSSH PRIVATE KEY-----',
    ],
    invalid: ['-----BEGIN PUBLIC KEY-----', '-----BEGIN CERTIFICATE-----'],
  },
  'firebase-fcm': {
    valid: ['AAAA1234567:' + 'a'.repeat(140)],
    invalid: ['AAAA123:short', 'AAAA1234567:' + 'a'.repeat(10)],
  },

  // Monitoring
  'newrelic': {
    valid: ['NRAK-' + 'A'.repeat(27)],
    invalid: ['NRAK-short', 'NRAK-' + 'A'.repeat(5)],
  },
  'newrelic-insight': {
    valid: ['NRIQ-' + 'A'.repeat(27)],
    invalid: ['NRIQ-short', 'NRIQ-' + 'A'.repeat(5)],
  },
  'sentry': {
    valid: ['sntrys_' + 'a'.repeat(40)],
    invalid: ['sntrys_short', 'sntrys_' + 'a'.repeat(5)],
  },
  'grafana': {
    valid: ['glc_' + 'a'.repeat(32)],
    invalid: ['glc_short', 'glc_' + 'a'.repeat(5)],
  },
  'linear': {
    valid: ['lin_api_' + 'a'.repeat(40)],
    invalid: ['lin_api_short', 'lin_api_' + 'a'.repeat(5)],
  },
};

describe('CREDENTIAL_PATTERNS', () => {
  // Parametric: every pattern matches its valid samples
  for (const pattern of CREDENTIAL_PATTERNS) {
    const testCase = PATTERN_TEST_CASES[pattern.id];
    if (!testCase) continue;

    describe(pattern.id, () => {
      for (const valid of testCase.valid) {
        it(`matches valid sample: ${valid.substring(0, 40)}...`, () => {
          expect(pattern.regex.test(valid)).toBe(true);
        });
      }

      for (const invalid of testCase.invalid) {
        it(`rejects invalid sample: ${invalid.substring(0, 40)}...`, () => {
          expect(pattern.regex.test(invalid)).toBe(false);
        });
      }
    });
  }

  it('has test cases for every pattern', () => {
    const missing = CREDENTIAL_PATTERNS.filter(p => !PATTERN_TEST_CASES[p.id]).map(p => p.id);
    expect(missing).toEqual([]);
  });

  it('has no duplicate pattern IDs', () => {
    const ids = CREDENTIAL_PATTERNS.map(p => p.id);
    const unique = [...new Set(ids)];
    expect(ids).toEqual(unique);
  });

  it('orders specific sk- prefixes before openai-legacy catch-all', () => {
    const ids = CREDENTIAL_PATTERNS.map(p => p.id);
    const anthropicIdx = ids.indexOf('anthropic');
    const openaiProjIdx = ids.indexOf('openai-proj');
    const openrouterIdx = ids.indexOf('openrouter');
    const openaiLegacyIdx = ids.indexOf('openai-legacy');

    expect(anthropicIdx).toBeLessThan(openaiLegacyIdx);
    expect(openaiProjIdx).toBeLessThan(openaiLegacyIdx);
    expect(openrouterIdx).toBeLessThan(openaiLegacyIdx);
  });

  it('orders stripe-test and stripe-restricted before stripe live', () => {
    const ids = CREDENTIAL_PATTERNS.map(p => p.id);
    const stripeTestIdx = ids.indexOf('stripe-test');
    const stripeRestrictedIdx = ids.indexOf('stripe-restricted');
    const stripeIdx = ids.indexOf('stripe');

    expect(stripeTestIdx).toBeLessThan(stripeIdx);
    expect(stripeRestrictedIdx).toBeLessThan(stripeIdx);
  });

  it('every pattern has a category', () => {
    const missing = CREDENTIAL_PATTERNS.filter(p => !p.category).map(p => p.id);
    expect(missing).toEqual([]);
  });

  it('no regex causes ReDoS on adversarial input (completes within 50ms)', () => {
    // Adversarial string: repeated characters that could cause backtracking
    const adversarial = 'a'.repeat(10000);
    for (const pattern of CREDENTIAL_PATTERNS) {
      const start = performance.now();
      pattern.regex.test(adversarial);
      const elapsed = performance.now() - start;
      expect(elapsed, `Pattern ${pattern.id} took ${elapsed}ms on adversarial input`).toBeLessThan(50);
    }
  });

  // Issue #127 item 2: a single adversarial shape per pattern is a thin gate.
  // Every regex edit should clear these worst-case inputs within budget.
  const REDOS_INPUTS: Array<{ name: string; value: string; budgetMs?: number }> = [
    { name: 'empty string', value: '' },
    { name: 'single char', value: 'a' },
    { name: '1k repeated a', value: 'a'.repeat(1000) },
    { name: '10k repeated a', value: 'a'.repeat(10000) },
    { name: '10k repeated /', value: '/'.repeat(10000) },
    // Patterns that share `sk-` / `AKIA` / `ghp_` prefixes might over-backtrack
    // on inputs that match the prefix but fail the body.
    { name: '10k after sk-', value: 'sk-' + 'a'.repeat(10000) },
    { name: '10k after AKIA', value: 'AKIA' + 'A'.repeat(10000) },
    { name: '10k after ghp_', value: 'ghp_' + 'a'.repeat(10000) },
    { name: '10k newlines', value: '\n'.repeat(10000) },
    { name: 'mixed long', value: ('aB1_-/.' as string).repeat(2000) },
    // Scheme-literal stuffing: every failed match attempt at each scheme
    // occurrence must stay bounded, not rescan to end-of-line (the quadratic
    // blowup an unbounded userinfo/query run produces on a one-line file).
    // These carry a 500ms budget instead of 50ms: linear scanning of 20KB+
    // costs ~80-110ms best-of-3 on a 2-core CI runner, while the quadratic
    // regression this guards against measures 3,000-30,000ms there — the
    // budget still discriminates by 10-60x without flaking on slow hardware.
    { name: '20k repeated postgres://', value: 'postgres://'.repeat(2000), budgetMs: 500 },
    { name: '20k repeated redis://', value: 'redis://'.repeat(2500), budgetMs: 500 },
    { name: '20k repeated mongodb://', value: 'mongodb://'.repeat(2000), budgetMs: 500 },
    { name: 'postgres:// with long @-free tail', value: 'postgres://' + 'a:b/'.repeat(5000), budgetMs: 500 },
    { name: 'minified no-space db inventory', value: ('{"u":"postgres://h' + 'x'.repeat(60) + '/db"},').repeat(250), budgetMs: 500 },
    // Open-ended runs added for secretless-ai#135: a key name or prefix
    // followed by a long run the pattern can never complete.
    { name: '10k after AccountKey=', value: 'AccountKey=' + 'a'.repeat(10000) },
    { name: '10k after EAAA', value: 'EAAA' + 'a'.repeat(10000) },
    { name: 'xoxp- with 1k numeric groups', value: 'xoxp-' + '1234567890-'.repeat(1000) },
  ];

  for (const input of REDOS_INPUTS) {
    const budget = input.budgetMs ?? 50;
    it(`no regex causes ReDoS on adversarial input "${input.name}" (every pattern <${budget}ms)`, () => {
      for (const pattern of CREDENTIAL_PATTERNS) {
        // Best of 3: the first .test() pays regex-compile/JIT cost, and under
        // a parallel test run CPU contention can multiply one sample past the
        // budget. A real quadratic blowup is orders of magnitude over budget
        // on every sample, so the minimum still catches it.
        let elapsed = Infinity;
        for (let run = 0; run < 3; run++) {
          const start = performance.now();
          pattern.regex.test(input.value);
          elapsed = Math.min(elapsed, performance.now() - start);
        }
        expect(elapsed, `Pattern ${pattern.id} took ${elapsed}ms (best of 3) on "${input.name}"`).toBeLessThan(budget);
      }
    });
  }
});

describe('CREDENTIAL_PREFIX_QUICK_CHECK', () => {
  it('is a valid RegExp', () => {
    expect(CREDENTIAL_PREFIX_QUICK_CHECK).toBeInstanceOf(RegExp);
  });

  it('matches known credential prefixes', () => {
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('sk-ant-api03-xxx')).toBe(true);
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('sk-proj-xxx')).toBe(true);
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test(['AKIA', '1234567890123456'].join(''))).toBe(true);
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('ghp_abc')).toBe(true);
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('xoxb-123')).toBe(true);
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('gsk_abc')).toBe(true);
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('glpat-abc')).toBe(true);
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('npm_abc')).toBe(true);
  });

  it('does not match random text', () => {
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('hello world')).toBe(false);
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('just some normal text')).toBe(false);
  });

  it('derives "redis" from the rediss? pattern, not "rediss" (optional-quantifier trim)', () => {
    // A 'rediss' prefix would make consumers' ${VAR}-skip drop plain
    // redis:// lines before the real pattern runs — a silent miss.
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('redis://x')).toBe(true);
  });

  it('derives the ghu_ and EAAA prefixes (secretless-ai#135)', () => {
    // Without them a line holding ${VAR} and one of these tokens is skipped
    // before the pattern runs.
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('ghu_abc')).toBe(true);
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('token: EAAA')).toBe(true);
  });
});

describe('vendor-format sweep (secretless-ai#135)', () => {
  // Vendors document these lengths as variable or growing, so a fixture pinned
  // to one length is what hid patterns that missed the format issued today.
  // Each pattern is swept at its documented minimum, one over, and well over,
  // and the match must reach the end of the value: a match that stops early
  // leaves the tail out of a redacted preview.
  const BODY = 'aB3xQ9zK7mR2tY5wL8pN4vC6hJ1sD0gF';
  const B64_BODY = 'aB3x+Q9zK7/mR2tY5wL8pN4vC6hJ1sD0gF';
  const HEX_BODY = '0f1e2d3c4b5a69788796a5b4c3d2e1f0';
  const run = (alphabet: string, n: number): string => alphabet.repeat(Math.ceil(n / alphabet.length)).slice(0, n);
  const pattern = (id: string) => {
    const p = CREDENTIAL_PATTERNS.find(c => c.id === id);
    if (!p) throw new Error(`catalog pattern ${id} not found`);
    return p;
  };

  const GITHUB = [
    { id: 'github-pat', prefix: 'ghp' },
    { id: 'github-oauth', prefix: 'gho' },
    { id: 'github-app', prefix: 'ghs' },
    { id: 'github-user-to-server', prefix: 'ghu' },
  ];
  const slack = (kind: 'b' | 'p', tail: string) =>
    kind === 'b'
      ? ['xox', 'b-', '123456789012-', '1234567890123-', tail].join('')
      : ['xox', 'p-', '123456789012-', '123456789012-', '1234567890123-', tail].join('');

  // Each row: the line a scanner reads, and the value the match must cover to its end.
  const VALID: Array<{ id: string; at: string; line: string; value: string }> = [
    // azure: 44 characters (32 bytes), one over, 88 characters (512-bit Storage key)
    ...[[43, '='], [44, '='], [86, '==']].map(([n, pad]) => {
      const value = run(B64_BODY, n as number) + pad;
      return { id: 'azure', at: `${(n as number) + (pad as string).length} chars`, line: 'AccountKey=' + value, value };
    }),
    // GitHub: 36 is today's body length; GitHub says to plan for 255 characters in all
    ...GITHUB.flatMap(({ id, prefix }) => [36, 37, 251].map(n => {
      const value = [prefix, '_', run(BODY, n)].join('');
      return { id, at: `${value.length} chars`, line: `token = "${value}"`, value };
    })),
    // Slack bot token: two numeric groups, secret at the pattern floor, one over, well over
    ...[24, 25, 80].map(n => {
      const value = slack('b', run(BODY, n));
      return { id: 'slack', at: `xoxb secret ${n}`, line: `SLACK_TOKEN=${value}`, value };
    }),
    // Slack user token: three numeric groups, 32-character secret, one over, well over
    ...[32, 33, 80].map(n => {
      const value = slack('p', run(HEX_BODY, n));
      return { id: 'slack', at: `xoxp secret ${n}`, line: `SLACK_TOKEN=${value}`, value };
    }),
    // Square: the documented 64-character token, quoted, unquoted, and as a bearer value
    ...['"%"', "'%'", 'token: %', 'Authorization: Bearer %', '%'].map(shape => {
      const value = ['EAAA', run(BODY, 60)].join('');
      return { id: 'square-access-token', at: shape, line: shape.replace('%', value), value };
    }),
  ];

  for (const { id, at, line, value } of VALID) {
    it(`${id} matches the whole value at ${at}`, () => {
      const m = line.match(pattern(id).regex);
      expect(m, `${id} no longer matches at ${at}`).not.toBeNull();
      const valueEnd = line.indexOf(value) + value.length;
      expect(m!.index! + m![0].length, `${id} stops before the end of the value at ${at}`).toBe(valueEnd);
      expect(m!.index!).toBeLessThanOrEqual(line.indexOf(value));
      expect(findRealMatch(line, pattern(id)), `${id} suppressed as an example at ${at}`).not.toBeNull();
    });
  }

  // Lines that must not produce a finding for each pattern this change touched.
  // A base64 blob can hold a prefix's letters but never its `_` or `-`
  // separator, so the blob rows carry the letters.
  const TOUCHED: Array<{ id: string; letters: string; placeholder: string }> = [
    { id: 'azure', letters: 'AccountKey', placeholder: 'AccountKey=' + 'EXAMPLE' + run(B64_BODY, 36) + '=' },
    { id: 'slack', letters: 'xoxp', placeholder: slack('p', 'placeholder' + run(HEX_BODY, 21)) },
    ...GITHUB.map(({ id, prefix }) => ({
      id, letters: prefix, placeholder: [prefix, '_', 'placeholder', run(BODY, 25)].join(''),
    })),
    { id: 'square-access-token', letters: 'EAAA', placeholder: ['EAAA', 'EXAMPLE', run(BODY, 53)].join('') },
  ];

  for (const { id, letters, placeholder } of TOUCHED) {
    const p = pattern(id);
    const blob = run(B64_BODY, 30) + letters + run(B64_BODY, 70);
    const nonMatching = [
      { what: 'sha512 integrity string', line: `"integrity": "sha512-${blob}=="` },
      { what: 'data: URI', line: `<img src="data:image/png;base64,${blob}">` },
      { what: 'its own regex source', line: `const re = /${p.regex.source}/${p.regex.flags};` },
      { what: '${VAR} reference', line: `AccountKey=\${${p.envPrefix}}` },
    ];
    for (const { what, line } of nonMatching) {
      it(`${id} does not match a ${what}`, () => {
        expect(p.regex.test(line)).toBe(false);
      });
    }
    it(`${id} matches a placeholder-marked value and the allowlist suppresses it`, () => {
      expect(p.regex.test(placeholder), `${id} placeholder fixture no longer has the token shape`).toBe(true);
      expect(findRealMatch(placeholder, p)).toBeNull();
    });
  }
});

describe('detection preserved for assembled fixtures', () => {
  // The families whose fixtures were whole in-source literals before being
  // assembled from parts; the live catalog must still see the assembled values.
  const AFFECTED_FAMILIES = ['anthropic', 'aws-access', 'aws-sts', 'github-pat', 'mongodb', 'google'];

  it('each affected family keeps a valid fixture matching the live catalog pattern, and assembled quick-check probes still pass', () => {
    for (const id of AFFECTED_FAMILIES) {
      const pattern = CREDENTIAL_PATTERNS.find(p => p.id === id);
      expect(pattern, `catalog pattern ${id}`).toBeDefined();
      const matched = PATTERN_TEST_CASES[id].valid.some(v => pattern!.regex.test(v));
      expect(matched, `family ${id} keeps a valid fixture matching the live pattern`).toBe(true);
    }
    expect(/^sk-ant-api\d{2}-/.test(anthropicTestKey)).toBe(true);
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test(['AKIA', '1234567890123456'].join(''))).toBe(true);
  });

  it('affected-family invalid fixtures still do not match — no detector weakened', () => {
    for (const id of AFFECTED_FAMILIES) {
      const pattern = CREDENTIAL_PATTERNS.find(p => p.id === id)!;
      for (const invalid of PATTERN_TEST_CASES[id].invalid) {
        expect(pattern.regex.test(invalid), `family ${id} still rejects: ${invalid}`).toBe(false);
      }
    }
  });
});

describe('CONFIG_FILES — MCP config coverage', () => {
  it('covers Claude Code project-scope .mcp.json (committed to repos)', () => {
    expect(CONFIG_FILES).toContain('.mcp.json');
  });

  it('covers the other org-known MCP/agent config locations', () => {
    expect(CONFIG_FILES).toContain('.mcp/config.json');
    expect(CONFIG_FILES).toContain('.claude/settings.local.json');
    expect(CONFIG_FILES).toContain('.windsurf/mcp.json');
  });

  it('covers .cursor/mcp.json under its real directory name (".curse" typo regression)', () => {
    expect(CONFIG_FILES).toContain('.cursor/mcp.json');
    expect(CONFIG_FILES.some(f => f.includes('.curse/'))).toBe(false);
  });
});
