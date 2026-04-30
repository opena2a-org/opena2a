import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { _resetKeychainForTests, getKeychain } from '../../src/util/keychain.js';

describe('keychain platform dispatch', () => {
  beforeEach(() => {
    _resetKeychainForTests();
  });

  afterEach(() => {
    _resetKeychainForTests();
    delete process.env.OPENA2A_AUTH_FORCE_FILE;
  });

  it('OPENA2A_AUTH_FORCE_FILE=1 returns the null backend on every platform', () => {
    process.env.OPENA2A_AUTH_FORCE_FILE = '1';
    const kc = getKeychain();
    expect(kc.isAvailable()).toBe(false);
    expect(kc.name).toBe('No keychain (file fallback)');
  });

  it('null backend returns null on getSecret and false on deleteSecret (no throw)', () => {
    process.env.OPENA2A_AUTH_FORCE_FILE = '1';
    const kc = getKeychain();
    expect(kc.getSecret('https://aim.oa2a.org', 'access')).toBeNull();
    expect(kc.deleteSecret('https://aim.oa2a.org', 'access')).toBe(false);
  });

  it('null backend setSecret throws (caller must check isAvailable first)', () => {
    process.env.OPENA2A_AUTH_FORCE_FILE = '1';
    const kc = getKeychain();
    expect(() => kc.setSecret('https://aim.oa2a.org', 'access', 'token')).toThrow(/not available/i);
  });

  it('caches the backend instance across calls', () => {
    process.env.OPENA2A_AUTH_FORCE_FILE = '1';
    const a = getKeychain();
    const b = getKeychain();
    expect(a).toBe(b);
  });

  it('platform-native backend identifies itself when not forced off', () => {
    delete process.env.OPENA2A_AUTH_FORCE_FILE;
    const kc = getKeychain();
    if (process.platform === 'darwin') {
      expect(kc.name).toBe('macOS Keychain');
    } else if (process.platform === 'linux') {
      expect(kc.name).toBe('Secret Service (libsecret)');
    } else {
      expect(kc.name).toBe('No keychain (file fallback)');
    }
  });
});
