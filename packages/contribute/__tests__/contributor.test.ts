import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { getContributorToken } from '../src/contributor.js';

const SALT_PATH = join(homedir(), '.opena2a', 'contributor-salt');

describe('contributor token', () => {
  let originalSalt: string | null = null;

  beforeEach(() => {
    // Back up existing salt if present
    if (existsSync(SALT_PATH)) {
      originalSalt = readFileSync(SALT_PATH, 'utf-8');
    }
  });

  afterEach(() => {
    // Restore original salt
    if (originalSalt !== null) {
      writeFileSync(SALT_PATH, originalSalt, { mode: 0o600 });
    }
  });

  it('returns a 64-char hex string (SHA-256)', () => {
    const token = getContributorToken();
    expect(token).toMatch(/^[a-f0-9]{64}$/);
  });

  it('returns the same token on repeated calls (stable)', () => {
    const token1 = getContributorToken();
    const token2 = getContributorToken();
    expect(token1).toBe(token2);
  });

  it('creates the salt file if missing', () => {
    // Remove salt temporarily
    const dir = join(homedir(), '.opena2a');
    const backupPath = join(dir, 'contributor-salt.bak');
    if (existsSync(SALT_PATH)) {
      writeFileSync(backupPath, readFileSync(SALT_PATH));
      rmSync(SALT_PATH);
    }

    try {
      const token = getContributorToken();
      expect(token).toMatch(/^[a-f0-9]{64}$/);
      expect(existsSync(SALT_PATH)).toBe(true);
    } finally {
      // Restore
      if (existsSync(backupPath)) {
        writeFileSync(SALT_PATH, readFileSync(backupPath), { mode: 0o600 });
        rmSync(backupPath);
      }
    }
  });
});
