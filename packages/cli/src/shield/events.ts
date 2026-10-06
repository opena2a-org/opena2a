/**
 * Shield tamper-evident event system.
 *
 * Events are stored as newline-delimited JSON (JSONL) with SHA-256 hash
 * chains.  Each event references the hash of the previous event, forming
 * an append-only tamper-evident log.  The very first event in the chain
 * uses SHA-256("genesis") as its prevHash.
 */

import { constants as bufferConstants } from 'node:buffer';
import { createHash, randomBytes } from 'node:crypto';
import {
  appendFileSync,
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  statSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { StringDecoder } from 'node:string_decoder';

import { getEventLockPath, withEventLock } from './lock.js';
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

/**
 * Return the absolute path to the Shield data directory.
 *
 * When `projectDir` is provided, uses a project-local `.opena2a/shield/`
 * directory (creating it if the project already has `.opena2a/`).
 * When omitted, falls back to the global `~/.opena2a/shield/`.
 *
 * @param projectDir  Optional project root.  When provided and the project
 *                    has a `.opena2a/` directory, events are stored locally.
 */
export function getShieldDir(projectDir?: string): string {
  let dir: string;

  if (projectDir) {
    const projectOpena2a = join(projectDir, '.opena2a');
    if (existsSync(projectOpena2a)) {
      dir = join(projectDir, '.opena2a', 'shield');
    } else {
      dir = join(homedir(), '.opena2a', 'shield');
    }
  } else {
    dir = join(homedir(), '.opena2a', 'shield');
  }

  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return dir;
}

/** Return the absolute path to the events JSONL file. */
export function getEventsPath(projectDir?: string): string {
  return join(getShieldDir(projectDir), SHIELD_EVENTS_FILE);
}

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

export const GENESIS_HASH = createHash('sha256').update('genesis').digest('hex');

/** Compute SHA-256 hex digest of a string. */
function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Read the chain tail the next event links to.
 *
 * `prevHash` is the eventHash of the last VALID event in the file.  A
 * trailing line that does not parse, is not an object, or carries no
 * eventHash (a torn append: crash, disk-full, kill mid-write) is skipped,
 * exactly as the reader skips it, and the chain continues from the event
 * before it.  Restarting at genesis there would put a genesis-linked event
 * in the middle of the file: a break the writer made itself, which review
 * cannot tell apart from tampering and which costs every later event its
 * trust (issue #244).  Genesis is returned only when the file holds no
 * valid event at all.
 *
 * `unterminated` is true when the file does not end in a newline, the
 * signature of a torn append.  The caller must start a new line first, or
 * the next event is glued onto the fragment and lost with it.
 */
function readChainTail(eventsPath: string): { prevHash: string; unterminated: boolean } {
  if (!existsSync(eventsPath)) return { prevHash: GENESIS_HASH, unterminated: false };

  let content: string;
  try {
    content = readFileSync(eventsPath, 'utf-8');
  } catch {
    return { prevHash: GENESIS_HASH, unterminated: false };
  }

  const unterminated = content.length > 0 && !content.endsWith('\n');

  const lines = content.split('\n');
  // Walk backwards to the last line that is a valid event
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (line.length === 0) continue;

    try {
      const parsed: unknown = JSON.parse(line);
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const eventHash = (parsed as { eventHash?: unknown }).eventHash;
        if (typeof eventHash === 'string' && eventHash.length > 0) {
          return { prevHash: eventHash, unterminated };
        }
      }
    } catch {
      // Torn or corrupted line -- keep walking back
    }
  }

  return { prevHash: GENESIS_HASH, unterminated };
}

/**
 * Timestamped sibling path for a retired events file:
 * `events.jsonl` -> `events-2026-08-10T12-00-00-000Z.jsonl`.
 *
 * Shared by size-based rotation and by `shield recover --archive-log`, so a
 * retired log has one recognisable shape however it was retired.
 */
export function rotatedEventsPath(eventsPath: string, at: Date = new Date()): string {
  const timestamp = at.toISOString().replace(/[:.]/g, '-');
  return eventsPath.replace(/\.jsonl$/, `-${timestamp}.jsonl`);
}

/**
 * Rotate the events file if it exceeds MAX_EVENTS_FILE_SIZE.
 * The current file is renamed with a timestamp suffix, and a fresh
 * file is started.
 *
 * Callers must hold the event lock: rotation racing an append would rename
 * the file out from under a writer that has already read its prevHash.
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

  renameSync(eventsPath, rotatedEventsPath(eventsPath));
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
 *
 * Read-prevHash and append are one critical section, held under the event
 * lock (see ./lock.ts).  Two unlocked writers read the same prevHash and
 * append two events claiming the same predecessor, which forks the chain
 * permanently -- and a forked chain now costs every later event its trust.
 * Rotation is inside the same section so a rename cannot land between a
 * writer's prevHash read and its append.
 *
 * @param partial     Event fields (minus auto-generated ones).
 * @param projectDir  Optional project root to write events to a
 *                    project-local `.opena2a/shield/` instead of global.
 */
export function writeEvent(
  partial: Omit<ShieldEvent, GeneratedFields>,
  projectDir?: string,
): ShieldEvent {
  const eventsPath = getEventsPath(projectDir);

  return withEventLock(getEventLockPath(eventsPath), () => {
    // Rotate before writing if the file is oversized
    rotateIfNeeded(eventsPath);

    const { prevHash, unterminated } = readChainTail(eventsPath);

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

    // Terminate a torn trailing fragment so this event starts its own line
    const line = (unterminated ? '\n' : '') + JSON.stringify(fullEvent) + '\n';

    // Ensure the shield directory exists (getEventsPath already calls getShieldDir)
    appendFileSync(eventsPath, line, { encoding: 'utf-8', mode: 0o600 });

    // Ensure restrictive permissions on the events file
    try {
      chmodSync(eventsPath, 0o600);
    } catch {
      // Best-effort; appendFileSync already set mode on creation
    }

    return fullEvent;
  });
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
  const relativeMatch = since.match(/^(\d+)([hdwm])$/);
  if (relativeMatch) {
    const amount = parseInt(relativeMatch[1], 10);
    const unit = relativeMatch[2];
    const now = Date.now();
    let ms: number;

    switch (unit) {
      case 'h':
        ms = amount * 60 * 60 * 1000;
        break;
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

// ---------------------------------------------------------------------------
// Chunked log reading
// ---------------------------------------------------------------------------

/** Bytes read per call: the reader's one fixed buffer. */
const READ_CHUNK_BYTES = 1024 * 1024;

/**
 * The longest line held for JSON.parse: the longest string the runtime can
 * create.  A longer line can never parse, so it is dropped as unreadable
 * as soon as it passes this length.
 */
const MAX_LINE_CHARS = bufferConstants.MAX_STRING_LENGTH;

/**
 * Call `onChunk` with each chunk of a regular file, in order, through one
 * fixed buffer that is reused for the next chunk once `onChunk` returns.
 *
 * Reads the size the file has when it is opened, as readFileSync does.
 * Anything that is not a regular file throws: a device has no end to stop at.
 */
function forEachChunk(path: string, chunkBytes: number, onChunk: (chunk: Buffer) => void): void {
  const fd = openSync(path, 'r');
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) {
      throw new Error(`Not a regular file: ${path}`);
    }

    const buffer = Buffer.alloc(Math.max(1, Math.min(chunkBytes, stat.size)));
    let remaining = stat.size;
    while (remaining > 0) {
      const read = readSync(fd, buffer, 0, Math.min(buffer.length, remaining), null);
      if (read === 0) break;
      remaining -= read;
      onChunk(read === buffer.length ? buffer : buffer.subarray(0, read));
    }
  } finally {
    closeSync(fd);
  }
}

/**
 * SHA-256 hex digest of a file's bytes, read in fixed chunks so a file of
 * any size is hashed without being held in memory.
 */
export function sha256File(path: string, chunkBytes: number = READ_CHUNK_BYTES): string {
  const hash = createHash('sha256');
  forEachChunk(path, chunkBytes, chunk => hash.update(chunk));
  return hash.digest('hex');
}

/**
 * Call `onLine` with each non-blank line of the log, trimmed as
 * `line.trim()` trims it, or with null for a non-blank line that cannot be
 * an event.  A line cannot be an event when its first character is not `{`
 * (JSON.parse would throw or return a non-object), and such a line is never
 * assembled; or when it is longer than `maxLineChars`, and such a line is
 * dropped as soon as it passes that length.
 *
 * Lines are split on '\n' after decoding.  The StringDecoder carries a
 * multi-byte character split across a chunk edge into the next chunk, so it
 * decodes once, exactly as a whole-file decode would.
 */
function forEachLogLine(
  path: string,
  limits: { chunkBytes: number; maxLineChars: number },
  onLine: (line: string | null) => void,
): void {
  const decoder = new StringDecoder('utf8');
  // blank: only whitespace so far.  held: assembling a line that opens with
  // '{'.  dropped: a non-blank line that cannot be an event.
  let state: 'blank' | 'held' | 'dropped' = 'blank';
  let pieces: string[] = [];
  let heldChars = 0;

  const take = (text: string): void => {
    if (state === 'blank') {
      const start = text.search(/\S/);
      if (start === -1) return;
      if (text[start] !== '{') {
        state = 'dropped';
        return;
      }
      state = 'held';
      text = text.slice(start);
    }
    if (state !== 'held') return;
    if (heldChars + text.length > limits.maxLineChars) {
      state = 'dropped';
      pieces = [];
      heldChars = 0;
      return;
    }
    pieces.push(text);
    heldChars += text.length;
  };

  const endLine = (): void => {
    if (state === 'held') onLine(pieces.join('').trim());
    else if (state === 'dropped') onLine(null);
    state = 'blank';
    pieces = [];
    heldChars = 0;
  };

  const split = (text: string): void => {
    let start = 0;
    let newline = text.indexOf('\n');
    while (newline !== -1) {
      take(text.slice(start, newline));
      endLine();
      start = newline + 1;
      newline = text.indexOf('\n', start);
    }
    if (start < text.length) take(text.slice(start));
  };

  forEachChunk(path, limits.chunkBytes, chunk => split(decoder.write(chunk)));
  split(decoder.end());
  endLine();
}

/** Parse one trimmed log line into an event, or null if it is not one. */
function parseEventLine(line: string): ShieldEvent | null {
  try {
    const parsed: unknown = JSON.parse(line);
    // Valid JSON that is not an object (null, scalar, array) cannot be
    // an event — treat it exactly like an unparseable corrupted line.
    // forEachLogLine already drops a line that does not open with '{';
    // this keeps the chain check total if that ever changes, since a
    // literal `null` would throw on property access there.
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    return parsed as ShieldEvent;
  } catch {
    return null;
  }
}

/**
 * The EventFilters a caller asked for, applied to events as they stream
 * past: every match is kept, or only the newest `count` matches when a
 * count is set.  `null` keeps nothing.
 */
function eventWindow(filters: EventFilters | null): {
  offer: (event: ShieldEvent) => void;
  newestFirst: () => ShieldEvent[];
} {
  const kept: ShieldEvent[] = [];
  const count = filters?.count !== undefined && filters.count > 0 ? filters.count : null;
  const sinceDate = filters?.since ? parseSince(filters.since) : null;
  const sinceMs = sinceDate ? sinceDate.getTime() : null;

  const matches = (e: ShieldEvent): boolean => {
    if (filters === null) return false;
    if (filters.source && e.source !== filters.source) return false;
    if (filters.severity && e.severity !== filters.severity) return false;
    if (filters.agent && e.agent !== filters.agent) return false;
    if (filters.category && e.category !== filters.category) return false;
    if (sinceMs !== null && !(new Date(e.timestamp).getTime() >= sinceMs)) return false;
    return true;
  };

  return {
    offer(event) {
      if (!matches(event)) return;
      kept.push(event);
      // Trim in batches so a long log costs one splice per `count` events.
      if (count !== null && kept.length >= 2 * count) {
        kept.splice(0, kept.length - count);
      }
    },
    // Newest-first (reverse chronological order), count limit applied
    // after reversing.
    newestFirst() {
      return (count === null ? kept.slice() : kept.slice(-count)).reverse();
    },
  };
}

/** Options for verifyEventLog. */
export interface EventLogReadOptions {
  /** The events to keep, as readEvents filters them.  The rest are only counted. */
  filters?: EventFilters;
  /** Keep no events: return only the verdict and the counts. */
  countsOnly?: boolean;
  /** Bytes per read.  Tests lower it to move the chunk edges. */
  chunkBytes?: number;
  /** Longest line held for JSON.parse.  Tests lower it. */
  maxLineChars?: number;
}

/** A chain-verified read, with the counts a caller needs beyond its window. */
export interface EventLogVerification extends VerifiedEventsResult {
  /** Events before the first chain break, in the caller's window or not. */
  trustedCount: number;
  /**
   * Non-blank lines that are not an event (unparseable, not a JSON object,
   * or longer than the longest line that can be parsed).  Skipped, as
   * review skips them.
   */
  unreadableLines: number;
}

/**
 * Read a log once, in fixed chunks, checking the hash chain line by line
 * when `verify` is set (otherwise every event counts as trusted).  A missing
 * log is empty; any other read failure throws.
 */
function scanEventLog(
  eventsPath: string,
  options: EventLogReadOptions,
  verify: boolean,
): EventLogVerification {
  const window = options.countsOnly ? null : (options.filters ?? {});
  const trusted = eventWindow(window);
  const untrusted = eventWindow(window);
  // One object, so the closure's writes are not narrowed away below.
  const scan = {
    index: 0,
    prevHash: GENESIS_HASH,
    brokenAt: null as number | null,
    firstUntrusted: null as ShieldEvent | null,
    unreadableLines: 0,
  };

  if (existsSync(eventsPath)) {
    const limits = {
      chunkBytes: options.chunkBytes ?? READ_CHUNK_BYTES,
      maxLineChars: options.maxLineChars ?? MAX_LINE_CHARS,
    };
    forEachLogLine(eventsPath, limits, line => {
      const event = line === null ? null : parseEventLine(line);
      if (event === null) {
        scan.unreadableLines++;
        return;
      }
      if (scan.brokenAt === null && (!verify || eventLinks(event, scan.prevHash))) {
        scan.prevHash = event.eventHash;
        trusted.offer(event);
      } else {
        if (scan.brokenAt === null) {
          scan.brokenAt = scan.index;
          scan.firstUntrusted = event;
        }
        untrusted.offer(event);
      }
      scan.index++;
    });
  }

  const untrustedCount = scan.brokenAt === null ? 0 : scan.index - scan.brokenAt;
  return {
    events: trusted.newestFirst(),
    untrusted: untrusted.newestFirst(),
    chainBroken: scan.brokenAt !== null,
    brokenAt: scan.brokenAt,
    untrustedCount,
    firstUntrusted: scan.firstUntrusted,
    trustedCount: scan.index - untrustedCount,
    unreadableLines: scan.unreadableLines,
  };
}

/**
 * Read events from the JSONL log file, applying optional filters.
 *
 * Returns events in newest-first order.  Corrupted JSON lines are
 * silently skipped.  Returns [] if the file is missing or unreadable.
 */
export function readEvents(filters: EventFilters = {}): ShieldEvent[] {
  const eventsPath = getEventsPath();
  try {
    return scanEventLog(eventsPath, { filters }, false).events;
  } catch {
    return [];
  }
}

/**
 * Result of a chain-verified event read (see readVerifiedEvents).
 */
export interface VerifiedEventsResult {
  /** Trusted events (before the first chain break), filtered, newest-first. */
  events: ShieldEvent[];
  /**
   * Events at or after the first chain break, filtered, newest-first.
   * Empty when the chain is intact.
   *
   * UNTRUSTED — forged, tampered, or corrupted.  Never classify these into
   * reported findings; doing so readmits the manufacture vectors the
   * exclusion exists to close.  They are exposed for one purpose only: a
   * caller can classify them for COUNTS, to learn what the same log would
   * have scored with an intact chain, and floor its score at that value.
   * Without that floor, corrupting one line scores BETTER than leaving the
   * log alone — blinding the sensor would beat forging into it.
   */
  untrusted: ShieldEvent[];
  /** True if the hash chain is broken anywhere in the log. */
  chainBroken: boolean;
  /** Chronological index of the first untrusted event, or null if intact. */
  brokenAt: number | null;
  /** Number of events at or after the break that were excluded. */
  untrustedCount: number;
  /** The event at the break point (untrusted; forensic evidence), or null. */
  firstUntrusted: ShieldEvent | null;
}

/**
 * Read events with hash-chain verification: verify the full chronological
 * log, with the same link check as verifyEventChain, and exclude every event
 * at or after the first chain break BEFORE applying filters (issue #204, the
 * "Option 2" of #111).
 *
 * The chain must be verified on the complete, unfiltered log — a time or
 * source filter would detach the first surviving event from its genesis
 * anchor and make verification meaningless.  Corrupted (unparseable or
 * non-object) lines are skipped at parse time; a corrupted line BETWEEN
 * genuine events surfaces as a break via the surviving neighbor's prevHash
 * mismatch, while trailing junk is skipped without one.
 *
 * GUARANTEE BOUNDARY — the chain is a keyless SHA-256 chain (no HMAC, no
 * secret; GENESIS_HASH is a public constant).  Verification therefore
 * detects accidental corruption, truncation, interleaved concurrent
 * writes, and naive appends that do not recompute the chain — which
 * covers forged findings injected without re-hashing (e.g. a forged
 * source:'shield' integrity critical, or a forged in-scope configguard
 * tamper event).  It does NOT stop an attacker who can write events.jsonl
 * and recomputes hashes with the public algorithm: such an attacker can
 * forge a validly-chained tail or rebuild the entire log from genesis.
 * Closing that requires a keyed MAC (with the key outside the log's
 * trust boundary) or an external anchor — a follow-up beyond issue #204.
 */
export function readVerifiedEvents(filters: EventFilters = {}): VerifiedEventsResult {
  const eventsPath = getEventsPath();
  let verification: EventLogVerification;
  try {
    verification = verifyEventLog(eventsPath, { filters });
  } catch {
    // A log that cannot be read reads as an empty one, as it always has.
    return {
      events: [], untrusted: [], chainBroken: false, brokenAt: null,
      untrustedCount: 0, firstUntrusted: null,
    };
  }
  const { trustedCount: _trusted, unreadableLines: _unreadable, ...result } = verification;
  return result;
}

/**
 * The chain-verified read behind readVerifiedEvents, for callers that need
 * the counts outside their window or must tell an unreadable log apart from
 * an empty one: it throws when the log exists but cannot be read.
 *
 * The log is read once in fixed chunks, never as one string, so a log of any
 * size gets the verdict its content warrants.  The chain is checked line by
 * line against the running prevHash, and only the events in the caller's
 * window are kept; the rest are counted.
 */
export function verifyEventLog(
  eventsPath: string,
  options: EventLogReadOptions = {},
): EventLogVerification {
  return scanEventLog(eventsPath, options, true);
}

/**
 * The synthetic event that surfaces a hash-chain break as the single
 * SHIELD-INT-002 finding.  It lives in memory only and is never written to
 * the log.  `review` and `shield report` both classify it through the normal
 * pipeline, so one break reads as one integrity critical on both surfaces
 * and the excluded events contribute nothing else.
 */
export function chainBreakEvent(
  verified: Pick<VerifiedEventsResult, 'brokenAt' | 'untrustedCount'>,
  surface: 'review' | 'report',
): ShieldEvent {
  return {
    id: uuidv7(),
    timestamp: new Date().toISOString(),
    version: 1,
    source: 'shield',
    category: 'integrity',
    severity: 'critical',
    agent: null,
    sessionId: null,
    action: 'event-chain-break',
    target: 'events.jsonl',
    outcome: 'blocked',
    detail: {
      brokenAt: verified.brokenAt,
      untrustedEventsExcluded: verified.untrustedCount,
      reason: `Event log hash chain break detected at ${surface} time; events at and after the break were excluded from classification.`,
    },
    prevHash: '',
    eventHash: '',
    orgId: null,
    managed: false,
    agentId: null,
  };
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
  for (let i = 0; i < events.length; i++) {
    const prevHash = i === 0 ? GENESIS_HASH : events[i - 1].eventHash;
    if (!eventLinks(events[i], prevHash)) {
      return { valid: false, brokenAt: i };
    }
  }

  return { valid: true, brokenAt: null };
}

/**
 * One link of the chain: `event` names `prevHash` (the previous event's
 * eventHash, or genesis) and its eventHash matches its own content.
 */
function eventLinks(event: ShieldEvent, prevHash: string): boolean {
  // 1. Verify prevHash links to the previous event (or genesis)
  if (event.prevHash !== prevHash) return false;

  // 2. Verify the eventHash matches the event content
  // Reconstruct the event without eventHash and compute the hash
  const { eventHash: _storedHash, ...rest } = event;
  return sha256(JSON.stringify(rest)) === event.eventHash;
}
