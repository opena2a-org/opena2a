import { describe, it, expect } from 'vitest';
import { CREDENTIAL_PATTERNS, expandValueToFullToken } from '../../src/util/credential-patterns.js';

function findPattern(id: string) {
  const p = CREDENTIAL_PATTERNS.find(p => p.id === id);
  if (!p) throw new Error(`Pattern ${id} not registered`);
  return p;
}

function fresh(re: RegExp): RegExp {
  return new RegExp(re.source, re.flags);
}

describe('credential patterns', () => {
  describe('CRED-006 Slack', () => {
    const pattern = () => findPattern('CRED-006').pattern;

    it('matches xoxb bot token', () => {
      const token = 'xoxb-1234567890-abcdefghijklmnopqrstuvwx';
      expect(fresh(pattern()).test(token)).toBe(true);
    });

    it('matches xoxp user token', () => {
      const token = 'xoxp-1234567890-abcdefghijklmnopqrstuvwx';
      expect(fresh(pattern()).test(token)).toBe(true);
    });

    it('matches xoxa app token', () => {
      const token = 'xoxa-1234567890-abcdefghijklmnopqrstuvwx';
      expect(fresh(pattern()).test(token)).toBe(true);
    });

    it('matches xoxr refresh token', () => {
      const token = 'xoxr-1234567890-abcdefghijklmnopqrstuvwx';
      expect(fresh(pattern()).test(token)).toBe(true);
    });

    it('does not match short xox prefix', () => {
      expect(fresh(pattern()).test('xoxb-short')).toBe(false);
    });

    it('does not match plain xox without dash', () => {
      expect(fresh(pattern()).test('xoxblahblahblahblah')).toBe(false);
    });
  });

  describe('CRED-007 Stripe', () => {
    const pattern = () => findPattern('CRED-007').pattern;

    it('matches sk_live_ secret key', () => {
      const key = 'sk_live_' + 'A'.repeat(24);
      expect(fresh(pattern()).test(key)).toBe(true);
    });

    it('matches sk_test_ secret key', () => {
      const key = 'sk_test_' + 'B'.repeat(40);
      expect(fresh(pattern()).test(key)).toBe(true);
    });

    it('does not match sk_live_ shorter than 24 chars after prefix', () => {
      const key = 'sk_live_' + 'A'.repeat(20);
      expect(fresh(pattern()).test(key)).toBe(false);
    });

    it('does not match plain sk_ prefix without live/test', () => {
      const key = 'sk_other_' + 'A'.repeat(24);
      expect(fresh(pattern()).test(key)).toBe(false);
    });
  });

  describe('CRED-003 GitHub token (extended to OAuth + refresh)', () => {
    const pattern = () => findPattern('CRED-003').pattern;

    it('matches ghp_ personal access token', () => {
      const token = 'ghp_' + 'A'.repeat(40);
      expect(fresh(pattern()).test(token)).toBe(true);
    });

    it('matches ghs_ server-to-server token', () => {
      const token = 'ghs_' + 'A'.repeat(40);
      expect(fresh(pattern()).test(token)).toBe(true);
    });

    it('matches ghu_ user-to-server OAuth token (regression for bug #10)', () => {
      const token = 'ghu_' + 'A'.repeat(40);
      expect(fresh(pattern()).test(token)).toBe(true);
    });

    it('matches ghr_ refresh token (regression for bug #10)', () => {
      const token = 'ghr_' + 'A'.repeat(40);
      expect(fresh(pattern()).test(token)).toBe(true);
    });

    it('does not match ghx_ (unknown prefix)', () => {
      const token = 'ghx_' + 'A'.repeat(40);
      expect(fresh(pattern()).test(token)).toBe(false);
    });

    it('does not match short github-style tokens', () => {
      const token = 'ghp_' + 'A'.repeat(20);
      expect(fresh(pattern()).test(token)).toBe(false);
    });
  });

  describe('CRED-004 Generic API Key (JSON-quoted-key form, bug #13)', () => {
    const pattern = () => findPattern('CRED-004').pattern;

    it('matches Python assignment without surrounding quotes on key', () => {
      const line = 'api_key="comp_fake_key_testing_only_1234567890abcdef"';
      expect(fresh(pattern()).test(line)).toBe(true);
    });

    it('matches JS-style apiKey property assignment', () => {
      const line = 'apiKey: "sk-mockmockmockmockmockmockmockmock"';
      expect(fresh(pattern()).test(line)).toBe(true);
    });

    it('matches vendor-prefixed JSON env key (regression for bug #13)', () => {
      // Real-world MCP env block: "WATSONX_API_KEY": "ibm-api-FAKE-..."
      // Prior regex demanded contiguous `key\s*[:=]` and missed the closing `"`
      // of the JSON key — same shape as the CRED-005 bug fixed earlier.
      const line = '"WATSONX_API_KEY": "ibm-api-FAKE-key-for-testing-1234567890"';
      const match = fresh(pattern()).exec(line);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('ibm-api-FAKE-key-for-testing-1234567890');
    });

    it('does NOT match ${VAR} placeholder values', () => {
      const line = '"API_KEY": "${API_KEY}"';
      expect(fresh(pattern()).test(line)).toBe(false);
    });

    it('does NOT match process.env references', () => {
      const line = 'const k = process.env.API_KEY;';
      expect(fresh(pattern()).test(line)).toBe(false);
    });

    it('does NOT match os.environ.get() with no value follow', () => {
      const line = 'os.environ.get("API_KEY")';
      expect(fresh(pattern()).test(line)).toBe(false);
    });

    it('does NOT match empty value', () => {
      const line = 'API_KEY: ""';
      expect(fresh(pattern()).test(line)).toBe(false);
    });
  });

  describe('CRED-005 AWS Secret Access Key (JSON-quoted format coverage, bug #11)', () => {
    const pattern = () => findPattern('CRED-005').pattern;

    it('matches .env shell-style assignment', () => {
      const line = 'AWS_SECRET_ACCESS_KEY=' + 'A'.repeat(40);
      expect(fresh(pattern()).test(line)).toBe(true);
    });

    it('matches code assignment with quoted value', () => {
      const line = `secretAccessKey = "${'B'.repeat(40)}"`;
      expect(fresh(pattern()).test(line)).toBe(true);
    });

    it('matches JSON object format with quoted key', () => {
      // The bug: prior to the fix, the pattern required `: "value` with no
      // closing quote on the key side, missing real-world JSON like
      //   "AWS_SECRET_ACCESS_KEY": "ABC..."
      const line = `"AWS_SECRET_ACCESS_KEY": "${'C'.repeat(40)}"`;
      expect(fresh(pattern()).test(line)).toBe(true);
    });

    it('matches camelCase variant in JSON', () => {
      const line = `"secretAccessKey": "${'D'.repeat(40)}"`;
      expect(fresh(pattern()).test(line)).toBe(true);
    });

    it('does not match values shorter than 40 chars', () => {
      const line = `AWS_SECRET_ACCESS_KEY=${'A'.repeat(30)}`;
      expect(fresh(pattern()).test(line)).toBe(false);
    });

    it('captures the secret value in group 1', () => {
      const secret = 'X'.repeat(40);
      const line = `"AWS_SECRET_ACCESS_KEY": "${secret}"`;
      const match = fresh(pattern()).exec(line);
      expect(match).not.toBeNull();
      expect(match![1]).toBe(secret);
    });
  });

  describe('expandValueToFullToken (F2: per-pattern tail-class restriction)', () => {
    const awsTail = /[0-9A-Z]/;

    it('extends a 20-char AWS match to a 21-char source token (original bug #7/#12)', () => {
      const line = 'AKIAFAKE000TESTONLY11';
      // simulated regex match captured 20 chars
      expect(expandValueToFullToken(line, 0, 'AKIAFAKE000TESTONLY1', awsTail)).toBe('AKIAFAKE000TESTONLY11');
    });

    it('does NOT overshoot into a hostname after an AWS-shaped token (F2 regression)', () => {
      // Without tail-class: would consume `.amazonaws.com/path` because the
      // old class included `.` and `/`. With per-pattern uppercase-alnum:
      // expansion stops at `.`.
      const line = '"url": "https://AKIA1234567890ABCDEF.amazonaws.com/path"';
      const start = line.indexOf('AKIA');
      expect(expandValueToFullToken(line, start, 'AKIA1234567890ABCDEF', awsTail)).toBe('AKIA1234567890ABCDEF');
    });

    it('does NOT overshoot into a URL path after an AWS key', () => {
      const line = 'export AWS_KEY=AKIA1234567890ABCDEF/extra';
      const start = line.indexOf('AKIA');
      expect(expandValueToFullToken(line, start, 'AKIA1234567890ABCDEF', awsTail)).toBe('AKIA1234567890ABCDEF');
    });

    it('returns capture unchanged when tailChars is undefined', () => {
      // Variable-length patterns are already greedy in the regex itself —
      // expansion must be opt-in via tailChars to avoid overshoot.
      expect(expandValueToFullToken('foo123/bar', 0, 'foo', undefined)).toBe('foo');
    });

    it('returns capture unchanged when capturedValue is not found in line', () => {
      expect(expandValueToFullToken('hello', 0, 'world', awsTail)).toBe('world');
    });
  });
});
