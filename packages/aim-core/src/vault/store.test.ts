import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as nacl from 'tweetnacl';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { VaultStore } from './store';
import { zeroize } from './crypto';

describe('vault/store', () => {
  let tmpDir: string;
  let vaultDir: string;
  let agentKp: nacl.SignKeyPair;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-vault-test-'));
    vaultDir = path.join(tmpDir, 'vault');
    agentKp = nacl.sign.keyPair();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('init', () => {
    it('creates vault directory and vault.enc file', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);

      expect(store.exists()).toBe(true);
      expect(fs.existsSync(path.join(vaultDir, 'vault.enc'))).toBe(true);
    });

    it('vault file has correct structure', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);

      const raw = JSON.parse(fs.readFileSync(path.join(vaultDir, 'vault.enc'), 'utf-8'));
      expect(raw.formatVersion).toBe(1);
      expect(raw.agentId).toBe('aim_test123');
      expect(raw.ephemeralPublicKey).toBeTruthy();
      expect(raw.credentials).toEqual({});
      expect(raw.createdAt).toBeTruthy();
    });

    it('throws if vault already exists', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      expect(() => store.init('aim_test123', agentKp.secretKey)).toThrow('already initialized');
    });
  });

  describe('store + resolve round-trip', () => {
    it('stores and resolves a credential', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);

      const cred = new TextEncoder().encode('ghp_abc123def456');
      store.storeCredential('github', cred);

      const resolved = store.resolveCredential('github');
      expect(Buffer.from(resolved).toString()).toBe('ghp_abc123def456');
      zeroize(resolved);
    });

    it('stores multiple credentials in separate namespaces', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);

      store.storeCredential('github', new TextEncoder().encode('ghp_token'));
      store.storeCredential('aws', new TextEncoder().encode('AKIAIOSFODNN7'));

      const gh = store.resolveCredential('github');
      const aws = store.resolveCredential('aws');

      expect(Buffer.from(gh).toString()).toBe('ghp_token');
      expect(Buffer.from(aws).toString()).toBe('AKIAIOSFODNN7');

      zeroize(gh);
      zeroize(aws);
    });

    it('credentials are encrypted on disk — no plaintext', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);

      const secret = 'super_secret_credential_12345';
      store.storeCredential('test', new TextEncoder().encode(secret));

      // Read raw file and verify no plaintext
      const raw = fs.readFileSync(path.join(vaultDir, 'vault.enc'), 'utf-8');
      expect(raw).not.toContain(secret);
    });
  });

  describe('unlock (reopen existing vault)', () => {
    it('unlock with correct key allows resolve', () => {
      // Init and store
      const store1 = new VaultStore(vaultDir);
      store1.init('aim_test123', agentKp.secretKey);
      store1.storeCredential('github', new TextEncoder().encode('ghp_token'));
      store1.lock();

      // Reopen with new VaultStore instance
      const store2 = new VaultStore(vaultDir);
      store2.unlock(agentKp.secretKey);
      const resolved = store2.resolveCredential('github');
      expect(Buffer.from(resolved).toString()).toBe('ghp_token');
      zeroize(resolved);
    });

    it('unlock with wrong key fails on resolve (CR-006)', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      store.storeCredential('github', new TextEncoder().encode('ghp_token'));
      store.lock();

      // Try with different agent's key
      const wrongKp = nacl.sign.keyPair();
      const store2 = new VaultStore(vaultDir);
      store2.unlock(wrongKp.secretKey);
      expect(() => store2.resolveCredential('github')).toThrow('authentication tag mismatch');
    });
  });

  describe('listCredentials', () => {
    it('returns empty list for new vault', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      expect(store.listCredentials()).toEqual([]);
    });

    it('lists metadata without credential values', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      store.storeCredential('github', new TextEncoder().encode('token'));
      store.storeCredential('aws', new TextEncoder().encode('key'));

      const list = store.listCredentials();
      expect(list).toHaveLength(2);
      expect(list.map((c) => c.namespace).sort()).toEqual(['aws', 'github']);
      expect(list[0].version).toBeGreaterThan(0);
      expect(list[0].encryptedAt).toBeTruthy();
      // No credential value in the returned data
      expect(JSON.stringify(list)).not.toContain('token');
      expect(JSON.stringify(list)).not.toContain('key');
    });
  });

  describe('deleteCredential', () => {
    it('deletes an existing credential', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      store.storeCredential('github', new TextEncoder().encode('token'));

      expect(store.deleteCredential('github')).toBe(true);
      expect(store.listCredentials()).toHaveLength(0);
    });

    it('returns false for non-existent credential', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      expect(store.deleteCredential('nonexistent')).toBe(false);
    });

    it('deleted credential cannot be resolved', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      store.storeCredential('github', new TextEncoder().encode('token'));
      store.deleteCredential('github');

      expect(() => store.resolveCredential('github')).toThrow('No credential found');
    });
  });

  describe('rotateCredential', () => {
    it('increments version on rotation', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      store.storeCredential('github', new TextEncoder().encode('old_token'));

      const v1 = store.listCredentials().find((c) => c.namespace === 'github')!.version;
      store.rotateCredential('github', new TextEncoder().encode('new_token'));
      const v2 = store.listCredentials().find((c) => c.namespace === 'github')!.version;

      expect(v2).toBe(v1 + 1);
    });

    it('resolves to new credential after rotation', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      store.storeCredential('github', new TextEncoder().encode('old_token'));
      store.rotateCredential('github', new TextEncoder().encode('new_token'));

      const resolved = store.resolveCredential('github');
      expect(Buffer.from(resolved).toString()).toBe('new_token');
      zeroize(resolved);
    });

    it('throws if namespace does not exist', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      expect(() =>
        store.rotateCredential('nonexistent', new TextEncoder().encode('val'))
      ).toThrow('Cannot rotate');
    });
  });

  describe('namespace isolation', () => {
    it('agent A cannot decrypt agent B credentials', () => {
      const agentA = nacl.sign.keyPair();
      const agentB = nacl.sign.keyPair();

      // Agent A creates vault and stores credential
      const vaultA = path.join(tmpDir, 'vault-a');
      const storeA = new VaultStore(vaultA);
      storeA.init('agent_a', agentA.secretKey);
      storeA.storeCredential('secret', new TextEncoder().encode('agent_a_secret'));
      storeA.lock();

      // Agent B tries to unlock agent A's vault
      const storeB = new VaultStore(vaultA);
      storeB.unlock(agentB.secretKey);
      expect(() => storeB.resolveCredential('secret')).toThrow('authentication tag mismatch');
    });
  });

  describe('destroy', () => {
    it('removes vault file', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      expect(store.exists()).toBe(true);

      store.destroy();
      expect(store.exists()).toBe(false);
    });

    it('after destroy, resolve throws', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      store.storeCredential('github', new TextEncoder().encode('token'));
      store.destroy();

      expect(() => store.resolveCredential('github')).toThrow('Vault is locked');
    });
  });

  describe('locked vault operations', () => {
    it('storeCredential throws when locked', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      store.lock();

      expect(() =>
        store.storeCredential('ns', new TextEncoder().encode('val'))
      ).toThrow('Vault is locked');
    });

    it('resolveCredential throws when locked', () => {
      const store = new VaultStore(vaultDir);
      store.init('aim_test123', agentKp.secretKey);
      store.storeCredential('ns', new TextEncoder().encode('val'));
      store.lock();

      expect(() => store.resolveCredential('ns')).toThrow('Vault is locked');
    });
  });
});
