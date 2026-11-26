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

/** Set `p` to `mode`; best-effort, since some platforms (Windows) do not support it. */
function tightenMode(p: string, mode: number): void {
  try {
    fs.chmodSync(p, mode);
  } catch {
    // chmod is unsupported or not permitted here; the creating modes still apply
  }
}

/** Append `data` to `filePath`, created 0o600 and tightened to 0o600 if it already existed looser. */
function appendOwnerOnly(filePath: string, data: string): void {
  const fd = fs.openSync(filePath, 'a', 0o600);
  try {
    try {
      fs.fchmodSync(fd, 0o600);
    } catch {
      // chmod is unsupported or not permitted here; the creating mode still applies
    }
    fs.writeFileSync(fd, data, 'utf-8');
  } finally {
    fs.closeSync(fd);
  }
}

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

  // The vault audit log names every secret operation, so it is the owner's
  // alone: the directory is created 0o700 and the file 0o600, and a directory
  // or log left looser by an earlier version is tightened on every write.
  fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
  tightenMode(vaultDir, 0o700);
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

  appendOwnerOnly(filePath, JSON.stringify(fullEvent) + '\n');
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
