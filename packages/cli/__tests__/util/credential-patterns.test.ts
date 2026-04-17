import { describe, it, expect } from 'vitest';
import { CREDENTIAL_PATTERNS } from '../../src/util/credential-patterns.js';

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
});
