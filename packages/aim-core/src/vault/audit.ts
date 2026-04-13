/**
 * Vault audit logging.
 *
 * Append-only JSONL log of all vault operations — resolve, store, rotate,
 * delete, revoke, etc. Reuses the rotation pattern from the existing audit.ts.
 *
 * Every vault operation (success or failure) must produce an audit entry.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import type {
  VaultAuditEvent,
  VaultAuditEventInput,
  VaultAuditReadOptions,
} from './types';

const VAULT_AUDIT_FILE = 'vault-audit.jsonl';
const MAX_AUDIT_SIZE = 50 * 1024 * 1024; // 50MB
const MAX_ROTATED_LOGS = 5;

/**
 * Log a vault audit event to the append-only JSONL file.
 *
 * @returns The complete event with timestamp
 */
export function logVaultEvent(
  vaultDir: string,
  event: VaultAuditEventInput
): VaultAuditEvent {
  const fullEvent: VaultAuditEvent = {
    timestamp: new Date().toISOString(),
    ...event,
  };

  fs.mkdirSync(vaultDir, { recursive: true });
  const filePath = path.join(vaultDir, VAULT_AUDIT_FILE);

  // Rotate if log exceeds size limit
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_AUDIT_SIZE) {
      const suffix = `${Date.now()}.${process.pid}.${crypto.randomBytes(4).toString('hex')}`;
      try {
        fs.renameSync(filePath, `${filePath}.${suffix}`);
      } catch {
        // Another process may have rotated
      }

      // Clean up old rotated logs
      try {
        const dir = path.dirname(filePath);
        const base = path.basename(filePath);
        const rotated = fs.readdirSync(dir)
          .filter((f: string) => f.startsWith(base + '.') && f !== base)
          .sort()
          .reverse();
        for (const old of rotated.slice(MAX_ROTATED_LOGS)) {
          try { fs.unlinkSync(path.join(dir, old)); } catch { /* best-effort */ }
        }
      } catch { /* best-effort */ }
    }
  } catch {
    // File doesn't exist yet
  }

  fs.appendFileSync(filePath, JSON.stringify(fullEvent) + '\n', 'utf-8');
  return fullEvent;
}

/**
 * Read vault audit events from the JSONL log.
 *
 * Supports filtering by limit, since timestamp, and namespace.
 */
export function readVaultAudit(
  vaultDir: string,
  options?: VaultAuditReadOptions
): VaultAuditEvent[] {
  const filePath = path.join(vaultDir, VAULT_AUDIT_FILE);
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const raw = fs.readFileSync(filePath, 'utf-8');
  const lines = raw.trim().split('\n').filter(Boolean);
  let events: VaultAuditEvent[] = lines.map((line) => JSON.parse(line) as VaultAuditEvent);

  if (options?.since) {
    const sinceTime = new Date(options.since).getTime();
    events = events.filter((e) => new Date(e.timestamp).getTime() > sinceTime);
  }

  if (options?.namespace) {
    events = events.filter((e) => e.namespace === options.namespace);
  }

  if (options?.limit && options.limit > 0) {
    events = events.slice(-options.limit);
  }

  return events;
}
