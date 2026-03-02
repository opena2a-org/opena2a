/**
 * Shield tamper-evident event system.
 *
 * Events are stored as newline-delimited JSON (JSONL) with SHA-256 hash
 * chains.  Each event references the hash of the previous event, forming
 * an append-only tamper-evident log.  The very first event in the chain
 * uses SHA-256("genesis") as its prevHash.
 */

import { createHash, randomBytes } from 'node:crypto';
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { ShieldEvent } from './types.js';
import { MAX_EVENTS_FILE_SIZE, SHIELD_EVENTS_FILE } from './types.js';

// ---------------------------------------------------------------------------
// UUIDv7 (RFC 9562)
// ---------------------------------------------------------------------------

/**
 * Generate a UUIDv7 (time-sortable) per RFC 9562.
 *
 * Layout (128 bits):
 *   48 bits - unix_ts_ms
 *    4 bits - version (0b0111)
 *   12 bits - rand_a
 *    2 bits - variant (0b10)
 *   62 bits - rand_b
 */
export function uuidv7(): string {
  const now = Date.now();
  const rand = randomBytes(10); // 80 random bits; we use 74

  // Bytes 0-5: 48-bit unix timestamp in milliseconds (big-endian)
  const buf = Buffer.alloc(16);
  buf[0] = (now / 2 ** 40) & 0xff;
  buf[1] = (now / 2 ** 32) & 0xff;
  buf[2] = (now / 2 ** 24) & 0xff;
  buf[3] = (now / 2 ** 16) & 0xff;
  buf[4] = (now / 2 ** 8) & 0xff;
  buf[5] = now & 0xff;

  // Bytes 6-7: version (4 bits = 0111) + rand_a (12 bits)
  buf[6] = 0x70 | (rand[0] & 0x0f);
  buf[7] = rand[1];

  // Bytes 8-15: variant (2 bits = 10) + rand_b (62 bits)
  buf[8] = 0x80 | (rand[2] & 0x3f);
  buf[9] = rand[3];
  buf[10] = rand[4];
  buf[11] = rand[5];
  buf[12] = rand[6];
  buf[13] = rand[7];
  buf[14] = rand[8];
  buf[15] = rand[9];

  const hex = buf.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

// ---------------------------------------------------------------------------
// Directory helpers
// ---------------------------------------------------------------------------

/** Return the absolute path to the Shield data directory (~/.opena2a/shield). */
export function getShieldDir(): string {
  const dir = join(homedir(), '.opena2a', 'shield');
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return dir;
}

/** Return the absolute path to the events JSONL file. */
export function getEventsPath(): string {
  return join(getShieldDir(), SHIELD_EVENTS_FILE);
}

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

const GENESIS_HASH = createHash('sha256').update('genesis').digest('hex');

/** Compute SHA-256 hex digest of a string. */
function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Read the last non-empty line from a file.  Returns null if the file
 * does not exist or is empty.
 */
function readLastLine(filePath: string): string | null {
  if (!existsSync(filePath)) return null;

  let content: string;
  try {
    content = readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }

  const lines = content.split('\n');
  // Walk backwards to find the last non-empty line
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (line.length > 0) return line;
  }
  return null;
}

/**
 * Extract the prevHash for the next event by reading the eventHash
 * of the last event in the chain.  Returns the genesis hash if the
 * file is empty or missing.
 */
function getPrevHash(eventsPath: string): string {
  const lastLine = readLastLine(eventsPath);
  if (!lastLine) return GENESIS_HASH;

  try {
    const parsed = JSON.parse(lastLine) as ShieldEvent;
    if (parsed.eventHash && typeof parsed.eventHash === 'string') {
      return parsed.eventHash;
    }
  } catch {
    // Corrupted last line -- fall through to genesis
  }

  return GENESIS_HASH;
}

/**
 * Rotate the events file if it exceeds MAX_EVENTS_FILE_SIZE.
 * The current file is renamed with a timestamp suffix, and a fresh
 * file is started.
 */
function rotateIfNeeded(eventsPath: string): void {
  if (!existsSync(eventsPath)) return;

  let size: number;
  try {
    size = statSync(eventsPath).size;
  } catch {
    return;
  }

  if (size <= MAX_EVENTS_FILE_SIZE) return;

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const rotatedPath = eventsPath.replace(/\.jsonl$/, `-${timestamp}.jsonl`);
  renameSync(eventsPath, rotatedPath);
}

// ---------------------------------------------------------------------------
// writeEvent
// ---------------------------------------------------------------------------

/** Fields that writeEvent generates automatically. */
type GeneratedFields = 'id' | 'timestamp' | 'version' | 'prevHash' | 'eventHash';

/**
 * Write a new event to the tamper-evident log.
 *
 * The caller provides all event fields except id, timestamp, version,
 * prevHash, and eventHash -- those are generated automatically.
 */
export function writeEvent(partial: Omit<ShieldEvent, GeneratedFields>): ShieldEvent {
  const eventsPath = getEventsPath();

  // Rotate before writing if the file is oversized
  rotateIfNeeded(eventsPath);

  const prevHash = getPrevHash(eventsPath);

  // Build the event without the final eventHash
  const event: Omit<ShieldEvent, 'eventHash'> & { eventHash?: string } = {
    id: uuidv7(),
    timestamp: new Date().toISOString(),
    version: 1,
    ...partial,
    prevHash,
  };

  // Compute the hash over the event (without the eventHash field itself)
  const hashInput = JSON.stringify(event);
  const eventHash = sha256(hashInput);

  const fullEvent: ShieldEvent = {
    ...(event as Omit<ShieldEvent, 'eventHash'>),
    eventHash,
  };

  const line = JSON.stringify(fullEvent) + '\n';

  // Ensure the shield directory exists (getEventsPath already calls getShieldDir)
  appendFileSync(eventsPath, line, { encoding: 'utf-8', mode: 0o600 });

  // Ensure restrictive permissions on the events file
  try {
    chmodSync(eventsPath, 0o600);
  } catch {
    // Best-effort; appendFileSync already set mode on creation
  }

  return fullEvent;
}

// ---------------------------------------------------------------------------
// readEvents
// ---------------------------------------------------------------------------

export interface EventFilters {
  count?: number;
  source?: string;
  severity?: string;
  agent?: string;
  since?: string;   // ISO 8601 or relative: "7d", "1w", "1m"
  category?: string;
}

/**
 * Parse a relative time string into a Date.
 *
 * Supported formats:
 *   "7d"  - 7 days ago
 *   "1w"  - 1 week ago
 *   "2w"  - 2 weeks ago
 *   "1m"  - 1 month ago (30 days)
 *   "3m"  - 3 months ago (90 days)
 *
 * If the string is not a relative format, it is parsed as ISO 8601.
 * Returns null if parsing fails entirely.
 */
function parseSince(since: string): Date | null {
  const relativeMatch = since.match(/^(\d+)([dwm])$/);
  if (relativeMatch) {
    const amount = parseInt(relativeMatch[1], 10);
    const unit = relativeMatch[2];
    const now = Date.now();
    let ms: number;

    switch (unit) {
      case 'd':
        ms = amount * 24 * 60 * 60 * 1000;
        break;
      case 'w':
        ms = amount * 7 * 24 * 60 * 60 * 1000;
        break;
      case 'm':
        ms = amount * 30 * 24 * 60 * 60 * 1000;
        break;
      default:
        return null;
    }

    return new Date(now - ms);
  }

  // Try ISO 8601
  const d = new Date(since);
  if (isNaN(d.getTime())) return null;
  return d;
}

/**
 * Read events from the JSONL log file, applying optional filters.
 *
 * Returns events in newest-first order.  Corrupted JSON lines are
 * silently skipped.
 */
export function readEvents(filters: EventFilters = {}): ShieldEvent[] {
  const eventsPath = getEventsPath();

  if (!existsSync(eventsPath)) return [];

  let content: string;
  try {
    content = readFileSync(eventsPath, 'utf-8');
  } catch {
    return [];
  }

  const lines = content.split('\n');
  const events: ShieldEvent[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;

    try {
      const event = JSON.parse(trimmed) as ShieldEvent;
      events.push(event);
    } catch {
      // Skip corrupted lines
      continue;
    }
  }

  // Apply filters
  let filtered = events;

  if (filters.source) {
    const src = filters.source;
    filtered = filtered.filter(e => e.source === src);
  }

  if (filters.severity) {
    const sev = filters.severity;
    filtered = filtered.filter(e => e.severity === sev);
  }

  if (filters.agent) {
    const agent = filters.agent;
    filtered = filtered.filter(e => e.agent === agent);
  }

  if (filters.category) {
    const cat = filters.category;
    filtered = filtered.filter(e => e.category === cat);
  }

  if (filters.since) {
    const sinceDate = parseSince(filters.since);
    if (sinceDate) {
      const sinceMs = sinceDate.getTime();
      filtered = filtered.filter(e => {
        const eventTime = new Date(e.timestamp).getTime();
        return eventTime >= sinceMs;
      });
    }
  }

  // Newest-first (reverse chronological order)
  filtered.reverse();

  // Apply count limit after reversing
  if (filters.count !== undefined && filters.count > 0) {
    filtered = filtered.slice(0, filters.count);
  }

  return filtered;
}

// ---------------------------------------------------------------------------
// verifyEventChain
// ---------------------------------------------------------------------------

/**
 * Verify the integrity of a hash chain.
 *
 * Events must be provided in chronological order (oldest first).
 * The first event's prevHash must equal SHA-256("genesis").
 *
 * Returns { valid: true, brokenAt: null } if the chain is intact,
 * or { valid: false, brokenAt: <index> } pointing to the first
 * event where the chain breaks.
 */
export function verifyEventChain(
  events: ShieldEvent[],
): { valid: boolean; brokenAt: number | null } {
  if (events.length === 0) {
    return { valid: true, brokenAt: null };
  }

  for (let i = 0; i < events.length; i++) {
    const event = events[i];

    // 1. Verify prevHash links to the previous event (or genesis)
    if (i === 0) {
      if (event.prevHash !== GENESIS_HASH) {
        return { valid: false, brokenAt: 0 };
      }
    } else {
      if (event.prevHash !== events[i - 1].eventHash) {
        return { valid: false, brokenAt: i };
      }
    }

    // 2. Verify the eventHash matches the event content
    // Reconstruct the event without eventHash and compute the hash
    const { eventHash: _storedHash, ...rest } = event;
    const computedHash = sha256(JSON.stringify(rest));
    if (computedHash !== event.eventHash) {
      return { valid: false, brokenAt: i };
    }
  }

  return { valid: true, brokenAt: null };
}
