import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as nacl from 'tweetnacl';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createResolutionRequest, resolveWithPolicy, type ResolutionContext } from './resolution';
import { VaultStore } from './store';
import { createNamespace, revokeNamespace } from './namespaces';
import { readVaultAudit } from './audit';
import { zeroize } from './crypto';

describe('vault/resolution', () => {
  let tmpDir: string;
  let vaultDir: string;
  let agentKp: nacl.SignKeyPair;
  let store: VaultStore;
  let context: ResolutionContext;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-resolve-test-'));
    vaultDir = path.join(tmpDir, 'vault');
    agentKp = nacl.sign.keyPair();

    // Init vault and store a credential
    store = new VaultStore(vaultDir);
    store.init('aim_test123', agentKp.secretKey);
    store.storeCredential('github', new TextEncoder().encode('ghp_real_token'));

    // Create namespace
    createNamespace(vaultDir, {
      id: 'github',
      description: 'GitHub API',
      agentId: 'aim_test123',
      operations: ['read', 'write'],
      urlPatterns: ['https://api.github.com/*'],
    });

    context = {
      vaultDir,
      store,
      edPublicKey: agentKp.publicKey,
    };
  });

  afterEach(() => {
    store.destroy();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('createResolutionRequest', () => {
    it('produces a signed request with nonce', () => {
      const req = createResolutionRequest('github', 'read', 'aim_test123', agentKp.secretKey);
      expect(req.namespace).toBe('github');
      expect(req.operation).toBe('read');
      expect(req.agentId).toBe('aim_test123');
      expect(req.signature).toBeTruthy();
      expect(req.nonce).toBeTruthy();
    });

    it('each request has a unique nonce', () => {
      const r1 = createResolutionRequest('github', 'read', 'aim_test123', agentKp.secretKey);
      const r2 = createResolutionRequest('github', 'read', 'aim_test123', agentKp.secretKey);
      expect(r1.nonce).not.toBe(r2.nonce);
    });
  });

  describe('resolveWithPolicy — success', () => {
    it('resolves a valid signed request', () => {
      const req = createResolutionRequest('github', 'read', 'aim_test123', agentKp.secretKey);
      const result = resolveWithPolicy(req, context);

      expect(result.success).toBe(true);
      expect(result.credential).toBeTruthy();
      expect(Buffer.from(result.credential!).toString()).toBe('ghp_real_token');
      expect(result.version).toBeGreaterThan(0);

      zeroize(result.credential!);
    });

    it('logs a granted audit event', () => {
      const req = createResolutionRequest('github', 'read', 'aim_test123', agentKp.secretKey);
      resolveWithPolicy(req, context);

      const events = readVaultAudit(vaultDir);
      expect(events).toHaveLength(1);
      expect(events[0].result).toBe('granted');
      expect(events[0].namespace).toBe('github');
    });
  });

  describe('resolveWithPolicy — invalid signature (CR-002)', () => {
    it('rejects request signed by wrong key', () => {
      const wrongKp = nacl.sign.keyPair();
      const req = createResolutionRequest('github', 'read', 'aim_test123', wrongKp.secretKey);

      const result = resolveWithPolicy(req, context);
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid signature');
      expect(result.credential).toBeUndefined();
    });

    it('logs denied audit event for bad signature', () => {
      const wrongKp = nacl.sign.keyPair();
      const req = createResolutionRequest('github', 'read', 'aim_test123', wrongKp.secretKey);
      resolveWithPolicy(req, context);

      const events = readVaultAudit(vaultDir);
      expect(events[0].result).toBe('denied');
      expect(events[0].denyReason).toContain('signature');
    });
  });

  describe('resolveWithPolicy — stale nonce (replay protection)', () => {
    it('rejects request with old nonce', () => {
      const req = createResolutionRequest('github', 'read', 'aim_test123', agentKp.secretKey);
      // Tamper nonce to be 5 minutes old
      const oldTime = new Date(Date.now() - 5 * 60 * 1000).toISOString();
      req.nonce = oldTime + '.abc123';
      // Re-sign with the tampered nonce
      const message = `${req.namespace}|${req.operation}|${req.nonce}`;
      const sig = nacl.sign.detached(new TextEncoder().encode(message), agentKp.secretKey);
      req.signature = Buffer.from(sig).toString('base64');

      const result = resolveWithPolicy(req, context);
      expect(result.success).toBe(false);
      expect(result.error).toContain('expired');
    });
  });

  describe('resolveWithPolicy — namespace not found', () => {
    it('rejects request for non-existent namespace', () => {
      const req = createResolutionRequest('nonexistent', 'read', 'aim_test123', agentKp.secretKey);
      const result = resolveWithPolicy(req, context);

      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });
  });

  describe('resolveWithPolicy — revoked namespace', () => {
    it('rejects request for revoked namespace', () => {
      revokeNamespace(vaultDir, 'github');

      const req = createResolutionRequest('github', 'read', 'aim_test123', agentKp.secretKey);
      const result = resolveWithPolicy(req, context);

      expect(result.success).toBe(false);
      expect(result.error).toContain('revoked');
    });

    it('logs denied with revoke reason', () => {
      revokeNamespace(vaultDir, 'github');
      const req = createResolutionRequest('github', 'read', 'aim_test123', agentKp.secretKey);
      resolveWithPolicy(req, context);

      const events = readVaultAudit(vaultDir);
      expect(events[0].denyReason).toContain('revoked');
    });
  });

  describe('resolveWithPolicy — operation not allowed', () => {
    it('rejects request with unauthorized operation', () => {
      // github namespace only allows 'read' and 'write'
      const req = createResolutionRequest('github', 'admin', 'aim_test123', agentKp.secretKey);
      const result = resolveWithPolicy(req, context);

      expect(result.success).toBe(false);
      expect(result.error).toContain('not allowed');
    });
  });

  describe('resolveWithPolicy — capability check (CR-003)', () => {
    it('rejects when capability checker denies', () => {
      const ctxWithCap: ResolutionContext = {
        ...context,
        checkCapability: () => false, // always deny
      };

      const req = createResolutionRequest('github', 'read', 'aim_test123', agentKp.secretKey);
      const result = resolveWithPolicy(req, ctxWithCap);

      expect(result.success).toBe(false);
      expect(result.error).toContain('capability');
    });

    it('allows when capability checker approves', () => {
      const ctxWithCap: ResolutionContext = {
        ...context,
        checkCapability: (cap) => cap === 'vault:resolve:github',
      };

      const req = createResolutionRequest('github', 'read', 'aim_test123', agentKp.secretKey);
      const result = resolveWithPolicy(req, ctxWithCap);

      expect(result.success).toBe(true);
      zeroize(result.credential!);
    });

    it('logs denied with missing capability reason', () => {
      const ctxWithCap: ResolutionContext = {
        ...context,
        checkCapability: () => false,
      };

      const req = createResolutionRequest('github', 'read', 'aim_test123', agentKp.secretKey);
      resolveWithPolicy(req, ctxWithCap);

      const events = readVaultAudit(vaultDir);
      expect(events[0].denyReason).toContain('capability');
    });
  });

  describe('resolveWithPolicy — all denials produce audit entries', () => {
    it('every failure path logs an audit event', () => {
      // 1. Bad signature
      const wrongKp = nacl.sign.keyPair();
      resolveWithPolicy(
        createResolutionRequest('github', 'read', 'a', wrongKp.secretKey),
        context
      );

      // 2. Non-existent namespace
      resolveWithPolicy(
        createResolutionRequest('no-ns', 'read', 'a', agentKp.secretKey),
        context
      );

      // 3. Revoked namespace
      createNamespace(vaultDir, {
        id: 'revoked-ns',
        description: 'Test',
        agentId: 'aim_test123',
        operations: ['read'],
        urlPatterns: [],
      });
      revokeNamespace(vaultDir, 'revoked-ns');
      resolveWithPolicy(
        createResolutionRequest('revoked-ns', 'read', 'a', agentKp.secretKey),
        context
      );

      // 4. Unauthorized operation
      resolveWithPolicy(
        createResolutionRequest('github', 'delete', 'a', agentKp.secretKey),
        context
      );

      const events = readVaultAudit(vaultDir);
      expect(events.filter((e) => e.result === 'denied')).toHaveLength(4);
    });
  });
});
