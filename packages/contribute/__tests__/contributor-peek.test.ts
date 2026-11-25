import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { getContributorToken, peekContributorToken } from '../src/contributor.js';

// `telemetry status` reports the contributor token, and a status command must
// not write anything: the peek reads the salt and never creates it.
describe('peekContributorToken', () => {
  let home: string;
  let savedHome: string | undefined;

  beforeEach(() => {
    savedHome = process.env.HOME;
    home = mkdtempSync(join(tmpdir(), 'contrib-peek-'));
    process.env.HOME = home;
  });

  afterEach(() => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    rmSync(home, { recursive: true, force: true });
  });

  it('returns null in a fresh HOME and creates nothing', () => {
    expect(peekContributorToken()).toBeNull();
    expect(readdirSync(home)).toEqual([]);
  });

  it('returns the token getContributorToken created, without changing it', () => {
    const token = getContributorToken();
    expect(existsSync(join(home, '.opena2a', 'contributor-salt'))).toBe(true);
    expect(peekContributorToken()).toBe(token);
    expect(getContributorToken()).toBe(token);
  });
});
