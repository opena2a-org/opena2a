import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { isContributeEnabled } from '../src/config.js';

const CONFIG_DIR = join(homedir(), '.opena2a');
const CONFIG_PATH = join(CONFIG_DIR, 'config.json');

describe('isContributeEnabled', () => {
  let originalConfig: string | null = null;

  beforeEach(() => {
    // Back up existing config
    if (existsSync(CONFIG_PATH)) {
      originalConfig = readFileSync(CONFIG_PATH, 'utf-8');
    }
  });

  afterEach(() => {
    // Restore original config
    if (originalConfig !== null) {
      writeFileSync(CONFIG_PATH, originalConfig, { mode: 0o600 });
    } else if (existsSync(CONFIG_PATH)) {
      // If there was no config before, remove what we created
      // (but leave it if it existed before the test suite)
    }
  });

  it('returns false when config file does not exist', () => {
    // Temporarily rename config
    const backupPath = CONFIG_PATH + '.test-bak';
    if (existsSync(CONFIG_PATH)) {
      writeFileSync(backupPath, readFileSync(CONFIG_PATH));
      rmSync(CONFIG_PATH);
    }
    try {
      expect(isContributeEnabled()).toBe(false);
    } finally {
      if (existsSync(backupPath)) {
        writeFileSync(CONFIG_PATH, readFileSync(backupPath), { mode: 0o600 });
        rmSync(backupPath);
      }
    }
  });

  it('returns false when contribute.enabled is false', () => {
    if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify({ contribute: { enabled: false } }), { mode: 0o600 });
    expect(isContributeEnabled()).toBe(false);
  });

  it('returns true when contribute.enabled is true', () => {
    if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify({ contribute: { enabled: true } }), { mode: 0o600 });
    expect(isContributeEnabled()).toBe(true);
  });

  it('returns false when config is malformed JSON', () => {
    if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_PATH, 'not json', { mode: 0o600 });
    expect(isContributeEnabled()).toBe(false);
  });

  it('returns false when contribute key is missing', () => {
    if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify({ version: 1 }), { mode: 0o600 });
    expect(isContributeEnabled()).toBe(false);
  });
});
