/**
 * Event Bridges — Cross-Tool Event Synchronization
 *
 * Reads events from each tool's native format and writes them to
 * AIM's audit log via aim.logEvent(). This creates a unified audit
 * trail across all OpenA2A tools.
 *
 * Follows the same pattern as shield/arp-bridge.ts but targets
 * AIM audit log instead of Shield's hash-chained event log.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AIMCoreLike {
  logEvent(event: {
    action: string;
    target: string;
    result: 'allowed' | 'denied' | 'error';
    plugin: string;
    metadata?: Record<string, unknown>;
  }): any;
  readAuditLog(opts?: { limit?: number }): Array<{
    action: string;
    target: string;
    result: string;
    plugin: string;
    metadata?: Record<string, unknown>;
    timestamp: string;
  }>;
}

export interface BridgeResult {
  imported: number;
  skipped: number;
  errors: number;
}

export interface BridgeResults {
  shield: BridgeResult;
  arp: BridgeResult;
  hma: BridgeResult;
  configguard: BridgeResult;
  secretless: BridgeResult;
  total: { imported: number; skipped: number; errors: number };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a set of already-imported source event IDs from existing AIM audit entries. */
function getImportedIds(aim: AIMCoreLike): Set<string> {
  const existing = aim.readAuditLog({ limit: 10000 });
  const ids = new Set<string>();
  for (const e of existing) {
    const sourceId = e.metadata?.sourceEventId;
    if (typeof sourceId === 'string') {
      ids.add(sourceId);
    }
  }
  return ids;
}

// ---------------------------------------------------------------------------
// Shield Events -> AIM Audit
// ---------------------------------------------------------------------------

export function importShieldEvents(aim: AIMCoreLike, opts?: { since?: string }): BridgeResult {
  const eventsPath = join(homedir(), '.opena2a', 'shield', 'events.jsonl');
  if (!existsSync(eventsPath)) return { imported: 0, skipped: 0, errors: 0 };

  let content: string;
  try {
    content = readFileSync(eventsPath, 'utf-8').trim();
  } catch {
    return { imported: 0, skipped: 0, errors: 0 };
  }

  if (!content) return { imported: 0, skipped: 0, errors: 0 };

  const lines = content.split('\n');
  const importedIds = getImportedIds(aim);
  const sinceMs = opts?.since ? new Date(opts.since).getTime() : 0;

  let imported = 0;
  let skipped = 0;
  let errors = 0;

  for (const line of lines) {
    let event: any;
    try {
      event = JSON.parse(line.trim());
    } catch {
      errors++;
      continue;
    }

    // Skip already-imported
    if (importedIds.has(event.id)) {
      skipped++;
      continue;
    }

    // Time filter
    if (sinceMs && new Date(event.timestamp).getTime() < sinceMs) {
      skipped++;
      continue;
    }

    // Skip shield's own ARP-bridged events to avoid double-counting
    // (ARP events are imported directly via importARPEvents)
    if (event.source === 'arp') {
      skipped++;
      continue;
    }

    const result: 'allowed' | 'denied' | 'error' =
      event.outcome === 'blocked' ? 'denied' :
      event.outcome === 'monitored' ? 'allowed' :
      'allowed';

    aim.logEvent({
      action: `shield.${event.action ?? event.category ?? 'event'}`,
      target: event.target ?? '',
      result,
      plugin: 'shield',
      metadata: {
        sourceEventId: event.id,
        severity: event.severity,
        category: event.category,
        outcome: event.outcome,
      },
    });
    imported++;
  }

  return { imported, skipped, errors };
}

// ---------------------------------------------------------------------------
// ARP Events -> AIM Audit
// ---------------------------------------------------------------------------

export function importARPEvents(aim: AIMCoreLike, targetDir: string): BridgeResult {
  const eventsPath = join(targetDir, '.opena2a', 'arp', 'events.jsonl');
  if (!existsSync(eventsPath)) return { imported: 0, skipped: 0, errors: 0 };

  let content: string;
  try {
    content = readFileSync(eventsPath, 'utf-8').trim();
  } catch {
    return { imported: 0, skipped: 0, errors: 0 };
  }

  if (!content) return { imported: 0, skipped: 0, errors: 0 };

  const lines = content.split('\n');
  const importedIds = getImportedIds(aim);
  let imported = 0;
  let skipped = 0;
  let errors = 0;

  for (const line of lines) {
    let event: any;
    try {
      event = JSON.parse(line.trim());
    } catch {
      errors++;
      continue;
    }

    if (importedIds.has(event.id)) {
      skipped++;
      continue;
    }

    const category = event.category ?? 'normal';
    const result: 'allowed' | 'denied' | 'error' =
      category === 'violation' || category === 'threat' ? 'denied' :
      category === 'anomaly' ? 'error' :
      'allowed';

    aim.logEvent({
      action: `arp.${event.source ?? 'unknown'}.${category}`,
      target: buildARPTarget(event),
      result,
      plugin: 'arp',
      metadata: {
        sourceEventId: event.id,
        severity: event.severity,
        description: event.description,
        classifiedBy: event.classifiedBy,
      },
    });
    imported++;
  }

  return { imported, skipped, errors };
}

function buildARPTarget(event: any): string {
  const data = event.data ?? {};
  if (data.command) return String(data.command);
  if (data.host) return String(data.host);
  if (data.path) return String(data.path);
  return event.description?.slice(0, 80) ?? 'unknown';
}

// ---------------------------------------------------------------------------
// HMA Scan Results -> AIM Audit
// ---------------------------------------------------------------------------

export function importHMAScanResults(aim: AIMCoreLike, targetDir: string): BridgeResult {
  // HMA stores scan results in various locations — check common ones
  const scanPaths = [
    join(targetDir, '.opena2a', 'hma', 'last-scan.json'),
    join(targetDir, '.opena2a', 'hma', 'scan-results.json'),
  ];

  let scanData: any = null;
  for (const p of scanPaths) {
    if (existsSync(p)) {
      try {
        scanData = JSON.parse(readFileSync(p, 'utf-8'));
        break;
      } catch { /* try next */ }
    }
  }

  if (!scanData) return { imported: 0, skipped: 0, errors: 0 };

  const importedIds = getImportedIds(aim);
  let imported = 0;
  let skipped = 0;

  // HMA scan results typically have a findings array
  const findings = scanData.findings ?? scanData.results ?? [];
  for (const finding of findings) {
    const id = finding.id ?? `hma-${finding.checkId ?? ''}-${finding.file ?? ''}`;
    if (importedIds.has(id)) {
      skipped++;
      continue;
    }

    aim.logEvent({
      action: `hma.${finding.checkId ?? finding.type ?? 'finding'}`,
      target: finding.file ?? finding.path ?? 'unknown',
      result: finding.severity === 'critical' || finding.severity === 'high' ? 'denied' : 'error',
      plugin: 'hma',
      metadata: {
        sourceEventId: id,
        severity: finding.severity,
        description: finding.message ?? finding.description,
        remediation: finding.remediation,
      },
    });
    imported++;
  }

  return { imported, skipped, errors: 0 };
}

// ---------------------------------------------------------------------------
// ConfigGuard State -> AIM Audit
// ---------------------------------------------------------------------------

export function importConfigGuardState(aim: AIMCoreLike, targetDir: string): BridgeResult {
  const sigFile = join(targetDir, '.opena2a', 'guard', 'signatures.json');
  if (!existsSync(sigFile)) return { imported: 0, skipped: 0, errors: 0 };

  let store: any;
  try {
    store = JSON.parse(readFileSync(sigFile, 'utf-8'));
  } catch {
    return { imported: 0, skipped: 0, errors: 0 };
  }

  const signatures = Array.isArray(store.signatures) ? store.signatures : [];
  if (signatures.length === 0) return { imported: 0, skipped: 0, errors: 0 };

  const importedIds = getImportedIds(aim);
  let imported = 0;
  let skipped = 0;

  for (const sig of signatures) {
    const id = `guard-${sig.filePath ?? ''}-${sig.signedAt ?? ''}`;
    if (importedIds.has(id)) {
      skipped++;
      continue;
    }

    aim.logEvent({
      action: 'configguard.sign',
      target: sig.filePath ?? 'unknown',
      result: 'allowed',
      plugin: 'configguard',
      metadata: {
        sourceEventId: id,
        hash: sig.hash,
        signedAt: sig.signedAt,
        signedBy: sig.signedBy,
      },
    });
    imported++;
  }

  return { imported, skipped, errors: 0 };
}

// ---------------------------------------------------------------------------
// Secretless State -> AIM Audit
// ---------------------------------------------------------------------------

export function importSecretlessState(aim: AIMCoreLike, targetDir: string): BridgeResult {
  const projectConfig = join(targetDir, '.secretless.json');
  const globalConfig = join(homedir(), '.secretless', 'config.json');

  const configPath = existsSync(projectConfig) ? projectConfig : existsSync(globalConfig) ? globalConfig : null;
  if (!configPath) return { imported: 0, skipped: 0, errors: 0 };

  const importedIds = getImportedIds(aim);
  const id = `secretless-config-${configPath}`;

  if (importedIds.has(id)) {
    return { imported: 0, skipped: 1, errors: 0 };
  }

  let config: any;
  try {
    config = JSON.parse(readFileSync(configPath, 'utf-8'));
  } catch {
    return { imported: 0, skipped: 0, errors: 1 };
  }

  const backend = config.backend ?? 'local';
  const secretCount = config.secrets ? Object.keys(config.secrets).length : 0;

  aim.logEvent({
    action: 'secretless.configured',
    target: configPath,
    result: 'allowed',
    plugin: 'secretless',
    metadata: {
      sourceEventId: id,
      backend,
      secretCount,
    },
  });

  return { imported: 1, skipped: 0, errors: 0 };
}

// ---------------------------------------------------------------------------
// Import all
// ---------------------------------------------------------------------------

/**
 * Import events from all enabled tools into AIM's audit log.
 * Only imports from tools that are enabled in the manifest (opt-in).
 */
export function importAllToolEvents(
  aim: AIMCoreLike,
  targetDir: string,
  enabledTools?: { shield?: boolean; arp?: boolean; hma?: boolean; configguard?: boolean; secretless?: boolean },
): BridgeResults {
  const tools = enabledTools ?? { shield: true, arp: true, hma: true, configguard: true, secretless: true };

  const shield = tools.shield ? importShieldEvents(aim) : { imported: 0, skipped: 0, errors: 0 };
  const arp = tools.arp ? importARPEvents(aim, targetDir) : { imported: 0, skipped: 0, errors: 0 };
  const hma = tools.hma ? importHMAScanResults(aim, targetDir) : { imported: 0, skipped: 0, errors: 0 };
  const configguard = tools.configguard ? importConfigGuardState(aim, targetDir) : { imported: 0, skipped: 0, errors: 0 };
  const secretless = tools.secretless ? importSecretlessState(aim, targetDir) : { imported: 0, skipped: 0, errors: 0 };

  const total = {
    imported: shield.imported + arp.imported + hma.imported + configguard.imported + secretless.imported,
    skipped: shield.skipped + arp.skipped + hma.skipped + configguard.skipped + secretless.skipped,
    errors: shield.errors + arp.errors + hma.errors + configguard.errors + secretless.errors,
  };

  return { shield, arp, hma, configguard, secretless, total };
}
