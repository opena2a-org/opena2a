import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  createNamespace,
  listNamespaces,
  getNamespace,
  updateNamespace,
  revokeNamespace,
} from './namespaces';

describe('vault/namespaces', () => {
  let tmpDir: string;
  let vaultDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-ns-test-'));
    vaultDir = path.join(tmpDir, 'vault');
    fs.mkdirSync(vaultDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('createNamespace', () => {
    it('creates a namespace with correct fields', () => {
      const ns = createNamespace(vaultDir, {
        id: 'github',
        description: 'GitHub API credentials',
        agentId: 'aim_test123',
        operations: ['read', 'write'],
        urlPatterns: ['https://api.github.com/*'],
      });

      expect(ns.id).toBe('github');
      expect(ns.description).toBe('GitHub API credentials');
      expect(ns.agentId).toBe('aim_test123');
      expect(ns.operations).toEqual(['read', 'write']);
      expect(ns.urlPatterns).toEqual(['https://api.github.com/*']);
      expect(ns.status).toBe('active');
      expect(ns.createdAt).toBeTruthy();
    });

    it('persists to disk', () => {
      createNamespace(vaultDir, {
        id: 'github',
        description: 'GitHub',
        agentId: 'aim_test123',
        operations: ['read'],
        urlPatterns: [],
      });

      const raw = JSON.parse(
        fs.readFileSync(path.join(vaultDir, 'namespaces.json'), 'utf-8')
      );
      expect(raw.namespaces.github).toBeTruthy();
    });

    it('throws on duplicate ID', () => {
      createNamespace(vaultDir, {
        id: 'github',
        description: 'GitHub',
        agentId: 'aim_test123',
        operations: ['read'],
        urlPatterns: [],
      });

      expect(() =>
        createNamespace(vaultDir, {
          id: 'github',
          description: 'Duplicate',
          agentId: 'aim_test123',
          operations: ['read'],
          urlPatterns: [],
        })
      ).toThrow('already exists');
    });
  });

  describe('listNamespaces', () => {
    it('returns empty array when no namespaces', () => {
      expect(listNamespaces(vaultDir)).toEqual([]);
    });

    it('lists all namespaces', () => {
      createNamespace(vaultDir, {
        id: 'github',
        description: 'GitHub',
        agentId: 'aim_test123',
        operations: ['read'],
        urlPatterns: [],
      });
      createNamespace(vaultDir, {
        id: 'aws',
        description: 'AWS',
        agentId: 'aim_test123',
        operations: ['read', 'write'],
        urlPatterns: [],
      });

      const list = listNamespaces(vaultDir);
      expect(list).toHaveLength(2);
      expect(list.map((ns) => ns.id).sort()).toEqual(['aws', 'github']);
    });
  });

  describe('getNamespace', () => {
    it('returns namespace by ID', () => {
      createNamespace(vaultDir, {
        id: 'github',
        description: 'GitHub',
        agentId: 'aim_test123',
        operations: ['read'],
        urlPatterns: ['https://api.github.com/*'],
      });

      const ns = getNamespace(vaultDir, 'github');
      expect(ns).not.toBeNull();
      expect(ns!.id).toBe('github');
    });

    it('returns null for non-existent namespace', () => {
      expect(getNamespace(vaultDir, 'nonexistent')).toBeNull();
    });
  });

  describe('updateNamespace', () => {
    it('updates description', () => {
      createNamespace(vaultDir, {
        id: 'github',
        description: 'Old',
        agentId: 'aim_test123',
        operations: ['read'],
        urlPatterns: [],
      });

      const updated = updateNamespace(vaultDir, 'github', {
        description: 'New description',
      });
      expect(updated.description).toBe('New description');
      // updatedAt is set on update — verify it's a valid ISO timestamp
      expect(updated.updatedAt).toBeTruthy();
      expect(new Date(updated.updatedAt).getTime()).toBeGreaterThanOrEqual(
        new Date(updated.createdAt).getTime()
      );
    });

    it('updates operations and URL patterns', () => {
      createNamespace(vaultDir, {
        id: 'github',
        description: 'GitHub',
        agentId: 'aim_test123',
        operations: ['read'],
        urlPatterns: [],
      });

      const updated = updateNamespace(vaultDir, 'github', {
        operations: ['read', 'write', 'admin'],
        urlPatterns: ['https://api.github.com/*'],
      });
      expect(updated.operations).toEqual(['read', 'write', 'admin']);
      expect(updated.urlPatterns).toEqual(['https://api.github.com/*']);
    });

    it('throws for non-existent namespace', () => {
      expect(() => updateNamespace(vaultDir, 'nonexistent', {})).toThrow('not found');
    });

    it('throws for revoked namespace', () => {
      createNamespace(vaultDir, {
        id: 'github',
        description: 'GitHub',
        agentId: 'aim_test123',
        operations: ['read'],
        urlPatterns: [],
      });
      revokeNamespace(vaultDir, 'github');

      expect(() =>
        updateNamespace(vaultDir, 'github', { description: 'New' })
      ).toThrow('revoked');
    });
  });

  describe('revokeNamespace', () => {
    it('revokes an active namespace', () => {
      createNamespace(vaultDir, {
        id: 'github',
        description: 'GitHub',
        agentId: 'aim_test123',
        operations: ['read'],
        urlPatterns: [],
      });

      const result = revokeNamespace(vaultDir, 'github');
      expect(result).toBe(true);

      const ns = getNamespace(vaultDir, 'github');
      expect(ns!.status).toBe('revoked');
    });

    it('returns false if already revoked', () => {
      createNamespace(vaultDir, {
        id: 'github',
        description: 'GitHub',
        agentId: 'aim_test123',
        operations: ['read'],
        urlPatterns: [],
      });
      revokeNamespace(vaultDir, 'github');

      expect(revokeNamespace(vaultDir, 'github')).toBe(false);
    });

    it('throws for non-existent namespace', () => {
      expect(() => revokeNamespace(vaultDir, 'nonexistent')).toThrow('not found');
    });

    it('revoked namespace still appears in list', () => {
      createNamespace(vaultDir, {
        id: 'github',
        description: 'GitHub',
        agentId: 'aim_test123',
        operations: ['read'],
        urlPatterns: [],
      });
      revokeNamespace(vaultDir, 'github');

      const list = listNamespaces(vaultDir);
      expect(list).toHaveLength(1);
      expect(list[0].status).toBe('revoked');
    });
  });
});
