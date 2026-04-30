/**
 * Auth storage tests. Use OPENA2A_AUTH_FORCE_FILE=1 + a tmp HOME so we never
 * touch the real keychain or the real ~/.opena2a/auth.json.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

let TMP_HOME: string;
let originalHome: string | undefined;

async function freshAuth() {
  // Re-import after env mutation so the AUTH_DIR const captures the tmp HOME.
  vi.resetModules();
  return await import('../../src/util/auth.js');
}

beforeEach(() => {
  TMP_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-auth-'));
  originalHome = process.env.HOME;
  process.env.HOME = TMP_HOME;
  process.env.OPENA2A_AUTH_FORCE_FILE = '1';
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  delete process.env.OPENA2A_AUTH_FORCE_FILE;
  fs.rmSync(TMP_HOME, { recursive: true, force: true });
});

describe('auth storage with keychain forced off (file-fallback path)', () => {
  it('saveAuth -> loadAuth round-trip writes tokens inline and returns "file"', async () => {
    const { saveAuth, loadAuth } = await freshAuth();
    const storage = saveAuth({
      serverUrl: 'https://aim.oa2a.org',
      accessToken: 'access-1',
      refreshToken: 'refresh-1',
      expiresAt: '2099-01-01T00:00:00Z',
      tokenType: 'Bearer',
      authenticatedAt: '2026-04-30T00:00:00Z',
    });
    expect(storage).toBe('file');

    const filePath = path.join(TMP_HOME, '.opena2a', 'auth.json');
    expect(fs.existsSync(filePath)).toBe(true);
    const onDisk = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    expect(onDisk.tokenStorage).toBe('file');
    expect(onDisk.accessToken).toBe('access-1');
    expect(onDisk.refreshToken).toBe('refresh-1');

    const loaded = loadAuth();
    expect(loaded).not.toBeNull();
    expect(loaded?.accessToken).toBe('access-1');
    expect(loaded?.refreshToken).toBe('refresh-1');
  });

  it('saveAuth writes the file with mode 0600', async () => {
    const { saveAuth } = await freshAuth();
    saveAuth({
      serverUrl: 'https://aim.oa2a.org',
      accessToken: 'access-2',
      refreshToken: 'refresh-2',
      expiresAt: '2099-01-01T00:00:00Z',
      tokenType: 'Bearer',
      authenticatedAt: '2026-04-30T00:00:00Z',
    });
    const filePath = path.join(TMP_HOME, '.opena2a', 'auth.json');
    const stat = fs.statSync(filePath);
    // 0o600 = owner rw only
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('removeAuth deletes the file', async () => {
    const { saveAuth, removeAuth, loadAuth } = await freshAuth();
    saveAuth({
      serverUrl: 'https://aim.oa2a.org',
      accessToken: 'access-3',
      refreshToken: 'refresh-3',
      expiresAt: '2099-01-01T00:00:00Z',
      tokenType: 'Bearer',
      authenticatedAt: '2026-04-30T00:00:00Z',
    });
    expect(removeAuth()).toBe(true);
    expect(loadAuth()).toBeNull();
  });

  it('loadAuth on a legacy file (tokens inline, no tokenStorage field) migrates and rewrites with tokenStorage="file"', async () => {
    // Write a legacy-shaped file by hand.
    const dir = path.join(TMP_HOME, '.opena2a');
    fs.mkdirSync(dir, { recursive: true });
    const legacy = {
      serverUrl: 'https://aim.oa2a.org',
      accessToken: 'legacy-access',
      refreshToken: 'legacy-refresh',
      expiresAt: '2099-01-01T00:00:00Z',
      tokenType: 'Bearer',
      authenticatedAt: '2026-04-30T00:00:00Z',
    };
    fs.writeFileSync(path.join(dir, 'auth.json'), JSON.stringify(legacy), { mode: 0o600 });

    const { loadAuth } = await freshAuth();
    const loaded = loadAuth();
    expect(loaded?.accessToken).toBe('legacy-access');

    // After migration, file MUST now have tokenStorage discriminator.
    const after = JSON.parse(fs.readFileSync(path.join(dir, 'auth.json'), 'utf-8'));
    expect(after.tokenStorage).toBe('file'); // forced-off → file fallback
    expect(after.accessToken).toBe('legacy-access');
  });

  it('loadAuth returns null when file is malformed JSON', async () => {
    const dir = path.join(TMP_HOME, '.opena2a');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'auth.json'), 'not-json{');
    const { loadAuth } = await freshAuth();
    expect(loadAuth()).toBeNull();
  });

  it('loadAuth returns null when tokenStorage="file" but tokens are missing', async () => {
    const dir = path.join(TMP_HOME, '.opena2a');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'auth.json'), JSON.stringify({
      serverUrl: 'https://aim.oa2a.org',
      expiresAt: '2099-01-01T00:00:00Z',
      tokenType: 'Bearer',
      authenticatedAt: '2026-04-30T00:00:00Z',
      tokenStorage: 'file',
      // accessToken / refreshToken missing — corrupted state
    }));
    const { loadAuth } = await freshAuth();
    expect(loadAuth()).toBeNull();
  });

  it('loadAuth returns null when tokenStorage="keychain" but keychain is empty (forced-off)', async () => {
    const dir = path.join(TMP_HOME, '.opena2a');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'auth.json'), JSON.stringify({
      serverUrl: 'https://aim.oa2a.org',
      expiresAt: '2099-01-01T00:00:00Z',
      tokenType: 'Bearer',
      authenticatedAt: '2026-04-30T00:00:00Z',
      tokenStorage: 'keychain',
    }));
    const { loadAuth } = await freshAuth();
    // Forced-off keychain returns null on getSecret -> loadAuth returns null
    expect(loadAuth()).toBeNull();
  });
});
