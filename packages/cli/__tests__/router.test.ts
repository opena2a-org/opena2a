import { describe, expect, it } from 'vitest';
import { isRichTarget } from '../src/router.js';

describe('isRichTarget — rich-block dispatch gate', () => {
  it('matches skill: prefix with slash-bearing name', () => {
    expect(isRichTarget('skill:opena2a/code-review-skill')).toBe(true);
  });

  it('matches mcp: prefix with @scope/name shape', () => {
    expect(isRichTarget('mcp:@modelcontextprotocol/server-filesystem')).toBe(true);
  });

  it('matches skill: with simple name (no slash)', () => {
    expect(isRichTarget('skill:my-skill')).toBe(true);
  });

  it('rejects empty name after prefix', () => {
    expect(isRichTarget('skill:')).toBe(false);
    expect(isRichTarget('mcp:')).toBe(false);
  });

  it('rejects unprefixed targets', () => {
    expect(isRichTarget('express')).toBe(false);
    expect(isRichTarget('@scope/pkg')).toBe(false);
    expect(isRichTarget('owner/repo')).toBe(false);
    expect(isRichTarget('pip:requests')).toBe(false);
  });

  it('rejects flag-style args', () => {
    expect(isRichTarget('--verbose')).toBe(false);
  });
});
