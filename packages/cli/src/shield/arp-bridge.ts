/**
 * ARP-Shield Event Bridge
 *
 * Translates ARP (Agent Runtime Protection) events into Shield's
 * tamper-evident hash chain. Supports both bulk import of existing
 * ARP event logs and live bridging during ARP monitoring.
 *
 * ARP events live in .opena2a/arp/events.jsonl (ARP native format).
 * Shield events live in ~/.opena2a/shield/events.jsonl (hash-chained).
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { writeEvent, readEvents } from './events.js';
import type { ShieldEvent, EventSeverity, EventOutcome, ShieldEventSource } from './types.js';

// ---------------------------------------------------------------------------
// ARP event shape (from hackmyagent/arp)
// ---------------------------------------------------------------------------

export interface ARPEvent {
  id: string;
  timestamp: string;
  source: string;    // 'process' | 'network' | 'filesystem' | 'prompt' | 'mcp-protocol' | 'a2a-protocol' | etc
  category: string;  // 'normal' | 'anomaly' | 'violation' | 'threat'
  severity: string;  // 'info' | 'low' | 'medium' | 'high' | 'critical'
  description: string;
  data: Record<string, unknown>;
  classifiedBy?: string;
  llmAssessment?: {
    consistent: boolean;
    confidence: number;
    reasoning: string;
    recommendation: string;
  };
}

// ---------------------------------------------------------------------------
// Translation
// ---------------------------------------------------------------------------

/** Map ARP category to Shield outcome. */
function mapOutcome(arpCategory: string, enforcement?: string): EventOutcome {
  if (enforcement === 'kill' || enforcement === 'pause') return 'blocked';
  if (arpCategory === 'violation' || arpCategory === 'threat') return 'blocked';
  if (arpCategory === 'anomaly') return 'monitored';
  return 'allowed';
}

/** Map ARP severity to Shield severity. */
function mapSeverity(arpSeverity: string): EventSeverity {
  const map: Record<string, EventSeverity> = {
    info: 'info',
    low: 'low',
    medium: 'medium',
    high: 'high',
    critical: 'critical',
  };
  return map[arpSeverity] ?? 'info';
}

/** Build a human-readable action string from ARP event data. */
function buildAction(arp: ARPEvent): string {
  const src = arp.source;
  const cat = arp.category;
  if (src === 'process') return `process.${cat === 'normal' ? 'spawn' : cat}`;
  if (src === 'network') return `network.${cat === 'normal' ? 'connection' : cat}`;
  if (src === 'filesystem') return `filesystem.${cat === 'normal' ? 'access' : cat}`;
  if (src === 'prompt') return `prompt.${cat}`;
  if (src === 'mcp-protocol') return `mcp.${cat}`;
  if (src === 'a2a-protocol') return `a2a.${cat}`;
  return `${src}.${cat}`;
}

/** Build a target string from ARP event data. */
function buildTarget(arp: ARPEvent): string {
  const data = arp.data ?? {};
  if (data.command) return String(data.command);
  if (data.host) return String(data.host);
  if (data.path) return String(data.path);
  if (data.name) return String(data.name);
  if (data.pid) return `pid:${data.pid}`;
  return arp.description?.slice(0, 80) ?? 'unknown';
}

/**
 * Translate a single ARP event into a Shield writeEvent partial.
 * This does NOT write the event -- caller decides when to persist.
 */
export function translateARPEvent(
  arp: ARPEvent,
  agentName?: string,
): Omit<ShieldEvent, 'id' | 'timestamp' | 'version' | 'prevHash' | 'eventHash'> {
  return {
    source: 'arp' as ShieldEventSource,
    category: `arp.${arp.source}`,
    severity: mapSeverity(arp.severity),
    agent: agentName ?? (arp.data?.agentName as string) ?? null,
    sessionId: null,
    action: buildAction(arp),
    target: buildTarget(arp),
    outcome: mapOutcome(arp.category, arp.llmAssessment?.recommendation),
    detail: {
      arpEventId: arp.id,
      arpSource: arp.source,
      arpCategory: arp.category,
      classifiedBy: arp.classifiedBy ?? 'L0-rules',
      description: arp.description,
      data: arp.data,
      ...(arp.llmAssessment ? { llmAssessment: arp.llmAssessment } : {}),
    },
    orgId: null,
    managed: false,
    agentId: null,
  };
}

// ---------------------------------------------------------------------------
// Bulk import
// ---------------------------------------------------------------------------

/**
 * Read ARP events from .opena2a/arp/events.jsonl and import them into
 * Shield's tamper-evident event log. Skips events that have already been
 * imported (checks for matching arpEventId in existing Shield events).
 *
 * Returns the count of newly imported events.
 */
export function importARPEvents(targetDir: string, agentName?: string): {
  imported: number;
  skipped: number;
  errors: number;
  total: number;
} {
  const arpEventsPath = join(targetDir, '.opena2a', 'arp', 'events.jsonl');

  if (!existsSync(arpEventsPath)) {
    return { imported: 0, skipped: 0, errors: 0, total: 0 };
  }

  let content: string;
  try {
    content = readFileSync(arpEventsPath, 'utf-8');
  } catch {
    return { imported: 0, skipped: 0, errors: 0, total: 0 };
  }

  const lines = content.trim().split('\n').filter(Boolean);

  // Build set of already-imported ARP event IDs
  const existingEvents = readEvents({ count: 10000, source: 'arp' });
  const importedIds = new Set<string>();
  for (const event of existingEvents) {
    const detail = event.detail as Record<string, unknown>;
    if (detail?.arpEventId) {
      importedIds.add(String(detail.arpEventId));
    }
  }

  let imported = 0;
  let skipped = 0;
  let errors = 0;

  for (const line of lines) {
    let arpEvent: ARPEvent;
    try {
      arpEvent = JSON.parse(line);
    } catch {
      errors++;
      continue;
    }

    // Skip already-imported events
    if (importedIds.has(arpEvent.id)) {
      skipped++;
      continue;
    }

    const partial = translateARPEvent(arpEvent, agentName);
    writeEvent(partial);
    imported++;
  }

  return { imported, skipped, errors, total: lines.length };
}

// ---------------------------------------------------------------------------
// ARP event stats (for shield report)
// ---------------------------------------------------------------------------

export interface ARPStats {
  totalEvents: number;
  anomalies: number;
  violations: number;
  threats: number;
  processEvents: number;
  networkEvents: number;
  filesystemEvents: number;
  promptEvents: number;
  enforcements: number;
}

/**
 * Compute stats from ARP events in Shield's log (source === 'arp').
 * Used by shield report to populate runtimeProtection section.
 */
export function getARPStats(since?: string): ARPStats {
  return computeARPStats(readEvents({ source: 'arp', since, count: 10000 }));
}

/**
 * Aggregate ARP stats from an already-loaded event list.  Pure — no I/O.
 * Lets callers that read events through a different path (e.g. review's
 * chain-verified read, issue #204) compute stats over the same trusted
 * event set they classify, instead of re-reading the raw log.
 */
export function computeARPStats(events: ShieldEvent[]): ARPStats {
  const stats: ARPStats = {
    totalEvents: events.length,
    anomalies: 0,
    violations: 0,
    threats: 0,
    processEvents: 0,
    networkEvents: 0,
    filesystemEvents: 0,
    promptEvents: 0,
    enforcements: 0,
  };

  for (const event of events) {
    const detail = event.detail as Record<string, unknown>;
    const arpCategory = String(detail?.arpCategory ?? '');

    if (arpCategory === 'anomaly') stats.anomalies++;
    if (arpCategory === 'violation') stats.violations++;
    if (arpCategory === 'threat') stats.threats++;

    if (event.category === 'arp.process') stats.processEvents++;
    if (event.category === 'arp.network') stats.networkEvents++;
    if (event.category === 'arp.filesystem') stats.filesystemEvents++;
    if (event.category === 'arp.prompt') stats.promptEvents++;

    if (event.outcome === 'blocked') stats.enforcements++;
  }

  return stats;
}
