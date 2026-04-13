import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { logVaultEvent, readVaultAudit } from './audit';

describe('vault/audit', () => {
  let tmpDir: string;
  let vaultDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-audit-test-'));
    vaultDir = path.join(tmpDir, 'vault');
    fs.mkdirSync(vaultDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('logVaultEvent', () => {
    it('writes JSONL format', () => {
      logVaultEvent(vaultDir, {
        agentId: 'aim_test123',
        namespace: 'github',
        operation: 'resolve',
        result: 'granted',
      });

      const raw = fs.readFileSync(
        path.join(vaultDir, 'vault-audit.jsonl'),
        'utf-8'
      );
      const lines = raw.trim().split('\n');
      expect(lines).toHaveLength(1);

      const event = JSON.parse(lines[0]);
      expect(event.agentId).toBe('aim_test123');
      expect(event.namespace).toBe('github');
      expect(event.operation).toBe('resolve');
      expect(event.result).toBe('granted');
      expect(event.timestamp).toBeTruthy();
    });

    it('appends multiple events', () => {
      logVaultEvent(vaultDir, {
        agentId: 'aim_test123',
        operation: 'vault:init',
        result: 'granted',
      });
      logVaultEvent(vaultDir, {
        agentId: 'aim_test123',
        namespace: 'github',
        operation: 'store',
        result: 'granted',
      });
      logVaultEvent(vaultDir, {
        agentId: 'aim_test123',
        namespace: 'github',
        operation: 'resolve',
        result: 'denied',
        denyReason: 'namespace revoked',
      });

      const events = readVaultAudit(vaultDir);
      expect(events).toHaveLength(3);
    });

    it('returns the full event with timestamp', () => {
      const event = logVaultEvent(vaultDir, {
        agentId: 'aim_test123',
        operation: 'vault:init',
        result: 'granted',
      });
      expect(event.timestamp).toBeTruthy();
      expect(event.agentId).toBe('aim_test123');
    });

    it('includes denial reason', () => {
      const event = logVaultEvent(vaultDir, {
        agentId: 'aim_test123',
        namespace: 'github',
        operation: 'resolve',
        result: 'denied',
        denyReason: 'invalid signature',
      });
      expect(event.denyReason).toBe('invalid signature');
    });

    it('includes optional metadata', () => {
      const event = logVaultEvent(vaultDir, {
        agentId: 'aim_test123',
        operation: 'resolve',
        result: 'granted',
        namespace: 'github',
        metadata: { version: 3, clientIp: '127.0.0.1' },
      });
      expect(event.metadata).toEqual({ version: 3, clientIp: '127.0.0.1' });
    });
  });

  describe('readVaultAudit', () => {
    it('returns empty array for non-existent log', () => {
      expect(readVaultAudit(vaultDir)).toEqual([]);
    });

    it('filters by since timestamp', () => {
      const t1 = new Date('2026-01-01T00:00:00Z');
      const t2 = new Date('2026-06-01T00:00:00Z');

      // Write events with known timestamps by writing directly
      const filePath = path.join(vaultDir, 'vault-audit.jsonl');
      fs.writeFileSync(filePath, [
        JSON.stringify({ timestamp: t1.toISOString(), agentId: 'a', operation: 'store', result: 'granted' }),
        JSON.stringify({ timestamp: t2.toISOString(), agentId: 'a', operation: 'resolve', result: 'granted' }),
      ].join('\n') + '\n');

      const events = readVaultAudit(vaultDir, { since: '2026-03-01T00:00:00Z' });
      expect(events).toHaveLength(1);
      expect(events[0].operation).toBe('resolve');
    });

    it('filters by namespace', () => {
      logVaultEvent(vaultDir, { agentId: 'a', namespace: 'github', operation: 'resolve', result: 'granted' });
      logVaultEvent(vaultDir, { agentId: 'a', namespace: 'aws', operation: 'resolve', result: 'granted' });
      logVaultEvent(vaultDir, { agentId: 'a', namespace: 'github', operation: 'rotate', result: 'granted' });

      const events = readVaultAudit(vaultDir, { namespace: 'github' });
      expect(events).toHaveLength(2);
      expect(events.every((e) => e.namespace === 'github')).toBe(true);
    });

    it('limits to most recent N events', () => {
      for (let i = 0; i < 10; i++) {
        logVaultEvent(vaultDir, {
          agentId: 'a',
          operation: 'resolve',
          result: 'granted',
          metadata: { index: i },
        });
      }

      const events = readVaultAudit(vaultDir, { limit: 3 });
      expect(events).toHaveLength(3);
      // Should be the last 3 events
      expect((events[0].metadata as Record<string, number>).index).toBe(7);
      expect((events[2].metadata as Record<string, number>).index).toBe(9);
    });

    it('combines filters', () => {
      logVaultEvent(vaultDir, { agentId: 'a', namespace: 'github', operation: 'resolve', result: 'granted' });
      logVaultEvent(vaultDir, { agentId: 'a', namespace: 'aws', operation: 'resolve', result: 'granted' });
      logVaultEvent(vaultDir, { agentId: 'a', namespace: 'github', operation: 'rotate', result: 'granted' });
      logVaultEvent(vaultDir, { agentId: 'a', namespace: 'github', operation: 'resolve', result: 'denied' });

      const events = readVaultAudit(vaultDir, { namespace: 'github', limit: 2 });
      expect(events).toHaveLength(2);
      expect(events[0].operation).toBe('rotate');
      expect(events[1].operation).toBe('resolve');
    });
  });
});
