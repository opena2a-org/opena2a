import { describe, expect, it } from 'vitest';
import { isRichTarget, isLocalPath } from '../src/router.js';

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

describe('isLocalPath — local-directory dispatch gate (#120)', () => {
  it('matches relative dot forms', () => {
    expect(isLocalPath('.')).toBe(true);
    expect(isLocalPath('..')).toBe(true);
    expect(isLocalPath('./test')).toBe(true);
    expect(isLocalPath('./packages/cli')).toBe(true);
    expect(isLocalPath('../sibling')).toBe(true);
  });

  it('matches absolute paths', () => {
    expect(isLocalPath('/Users/me/project')).toBe(true);
    expect(isLocalPath('/tmp')).toBe(true);
  });

  it('matches home-relative paths', () => {
    expect(isLocalPath('~')).toBe(true);
    expect(isLocalPath('~/workspace')).toBe(true);
  });

  it('rejects npm package names', () => {
    expect(isLocalPath('express')).toBe(false);
    expect(isLocalPath('@scope/pkg')).toBe(false);
    expect(isLocalPath('left-pad')).toBe(false);
  });

  it('rejects rich-target prefixes', () => {
    expect(isLocalPath('skill:my-skill')).toBe(false);
    expect(isLocalPath('mcp:server')).toBe(false);
    expect(isLocalPath('pip:requests')).toBe(false);
  });

  it('rejects github-style shorthand and hostnames', () => {
    expect(isLocalPath('owner/repo')).toBe(false);
    expect(isLocalPath('example.com')).toBe(false);
  });
});
