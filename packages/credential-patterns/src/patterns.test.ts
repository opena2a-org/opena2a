import { describe, it, expect } from 'vitest';
import { CONFIG_FILES, CREDENTIAL_PATTERNS, CREDENTIAL_PREFIX_QUICK_CHECK } from './patterns.js';

/**
 * Test data for each pattern: valid strings that MUST match, invalid strings that MUST NOT.
 *
 * Strings here are synthetic (mostly `'a'.repeat(n)` shape fixtures) — they exercise
 * regex shape, not real credentials. Tokens that look credential-shaped are built
 * dynamically to avoid triggering GitHub Push Protection on this file itself.
 */
// Build test tokens dynamically to avoid triggering GitHub Push Protection
const slackTestToken = ['xox', 'b-1234567890-1234567890-', 'abcdefghijklmnopqrstuvwx'].join('');
const discordBotToken = ['MTIzNDU2Nzg5MDEyMzQ1Njc4OQ', '.GabcDE.', 'abcdefghijklmnopqrstuvwxyz01234'].join('');

const PATTERN_TEST_CASES: Record<string, { valid: string[]; invalid: string[] }> = {
  // AI/ML
  'anthropic': {
    valid: ['sk-ant-api03-abc123def456abc123def456abc123'],
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
    valid: ['AKIAIOSFODNN7EXAMPLE'],
    invalid: ['AKIA123', 'BKIAIOSFODNN7EXAMPLE'],
  },
  'aws-sts': {
    valid: ['ASIAIOSFODNN7EXAMPLE'],
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
    valid: ['AccountKey=' + 'a'.repeat(43) + '=', 'SharedAccessKey = ' + 'B'.repeat(43) + '='],
    invalid: ['AccountKey=short', 'RandomKey=' + 'a'.repeat(43) + '='],
  },
  'supabase': {
    valid: ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + 'a'.repeat(50)],
    invalid: ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.short'],
  },

  // Communication
  'slack': {
    valid: [slackTestToken],
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
    valid: ['ghp_abcdefghijklmnopqrstuvwxyz0123456789'],
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

  // Database — connection strings flag only when a secret is embedded:
  // a userinfo password (or, for redis, any single userinfo token — pre-ACL
  // Redis has no usernames) or a password=/pwd=/sslpassword= query param.
  // Credential-free URIs are topology, not exposures, and matches must not
  // cross JSON string boundaries on minified content.
  'mongodb': {
    valid: [
      'mongodb+srv://user:pass@cluster.mongodb.net/db',
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
    valid: ['AIzaSyB-abc_def123456789012345678901234'],
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
  const REDOS_INPUTS: Array<{ name: string; value: string }> = [
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
    { name: '20k repeated postgres://', value: 'postgres://'.repeat(2000) },
    { name: '20k repeated redis://', value: 'redis://'.repeat(2500) },
    { name: '20k repeated mongodb://', value: 'mongodb://'.repeat(2000) },
    { name: 'postgres:// with long @-free tail', value: 'postgres://' + 'a:b/'.repeat(5000) },
    { name: 'minified no-space db inventory', value: ('{"u":"postgres://h' + 'x'.repeat(60) + '/db"},').repeat(250) },
  ];

  for (const input of REDOS_INPUTS) {
    it(`no regex causes ReDoS on adversarial input "${input.name}" (every pattern <50ms)`, () => {
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
        expect(elapsed, `Pattern ${pattern.id} took ${elapsed}ms (best of 3) on "${input.name}"`).toBeLessThan(50);
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
    expect(CREDENTIAL_PREFIX_QUICK_CHECK.test('AKIA1234567890123456')).toBe(true);
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
