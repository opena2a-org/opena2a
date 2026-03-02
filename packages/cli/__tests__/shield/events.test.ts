import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import type { ShieldEvent } from '../../src/shield/types.js';

// ---------------------------------------------------------------------------
// Mock node:os so that homedir() returns our temp directory.
// vi.mock is hoisted, so _mockHomeDir is set in beforeEach before any
// calls into the module under test.
// ---------------------------------------------------------------------------

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => _mockHomeDir,
  };
});

// Import the module under test AFTER vi.mock declaration (vitest hoists the mock).
const {
  uuidv7,
  getShieldDir,
  getEventsPath,
  writeEvent,
  readEvents,
  verifyEventChain,
} = await import('../../src/shield/events.js');

const GENESIS_HASH = createHash('sha256').update('genesis').digest('hex');

// ---------------------------------------------------------------------------
// Temp directory setup
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-events-test-'));
  _mockHomeDir = tempDir;
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Helper: build a minimal partial event for writeEvent
// ---------------------------------------------------------------------------

function makePartial(overrides: Partial<ShieldEvent> = {}) {
  return {
    source: 'shield' as const,
    category: 'test',
    severity: 'info' as const,
    agent: null,
    sessionId: null,
    action: 'test-action',
    target: 'test-target',
    outcome: 'monitored' as const,
    detail: {},
    orgId: null,
    managed: false,
    agentId: null,
    ...overrides,
  };
}

// ===========================================================================
// 1. uuidv7
// ===========================================================================

describe('uuidv7', () => {
  it('produces 8-4-4-4-12 hex format', () => {
    const id = uuidv7();
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it('has version nibble 7 (byte 6 high nibble)', () => {
    const id = uuidv7();
    // The version nibble is the first character of the third group
    const thirdGroup = id.split('-')[2];
    expect(thirdGroup[0]).toBe('7');
  });

  it('has variant bits 10 (byte 8 top 2 bits)', () => {
    const id = uuidv7();
    // The variant is the first character of the fourth group
    const fourthGroup = id.split('-')[3];
    const firstNibble = parseInt(fourthGroup[0], 16);
    // Top 2 bits must be 10 => value in [0x8, 0xb]
    expect(firstNibble).toBeGreaterThanOrEqual(0x8);
    expect(firstNibble).toBeLessThanOrEqual(0xb);
  });

  it('is time-sortable (UUIDs from different milliseconds sort correctly)', async () => {
    const a = uuidv7();
    // Wait 2ms to ensure different timestamp
    await new Promise(resolve => setTimeout(resolve, 2));
    const b = uuidv7();
    expect(b > a).toBe(true);
  });

  it('generates 100 unique values', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      ids.add(uuidv7());
    }
    expect(ids.size).toBe(100);
  });
});

// ===========================================================================
// 2. writeEvent + readEvents (basic round-trip)
// ===========================================================================

describe('writeEvent + readEvents', () => {
  it('writes 3 events and reads them back newest-first', () => {
    writeEvent(makePartial({ action: 'action-1' }));
    writeEvent(makePartial({ action: 'action-2' }));
    writeEvent(makePartial({ action: 'action-3' }));

    const events = readEvents();
    expect(events).toHaveLength(3);

    // Newest-first ordering
    expect(events[0].action).toBe('action-3');
    expect(events[1].action).toBe('action-2');
    expect(events[2].action).toBe('action-1');
  });

  it('each event has required generated fields', () => {
    const e = writeEvent(makePartial());
    expect(e.id).toBeDefined();
    expect(e.timestamp).toBeDefined();
    expect(e.version).toBe(1);
    expect(e.prevHash).toBeDefined();
    expect(e.eventHash).toBeDefined();
  });

  it('first event prevHash equals SHA-256("genesis")', () => {
    const e = writeEvent(makePartial());
    expect(e.prevHash).toBe(GENESIS_HASH);
  });

  it('second event prevHash equals first event eventHash', () => {
    const e1 = writeEvent(makePartial({ action: 'first' }));
    const e2 = writeEvent(makePartial({ action: 'second' }));
    expect(e2.prevHash).toBe(e1.eventHash);
  });
});

// ===========================================================================
// 3. readEvents filters
// ===========================================================================

describe('readEvents filters', () => {
  beforeEach(() => {
    writeEvent(makePartial({ source: 'hma', severity: 'high', agent: 'claude', category: 'scan' }));
    writeEvent(makePartial({ source: 'secretless', severity: 'low', agent: 'copilot', category: 'credential' }));
    writeEvent(makePartial({ source: 'hma', severity: 'critical', agent: 'claude', category: 'scan' }));
    writeEvent(makePartial({ source: 'arp', severity: 'medium', agent: 'cursor', category: 'runtime' }));
    writeEvent(makePartial({ source: 'shield', severity: 'info', agent: null, category: 'system' }));
  });

  it('filters by source', () => {
    const events = readEvents({ source: 'hma' });
    expect(events).toHaveLength(2);
    expect(events.every(e => e.source === 'hma')).toBe(true);
  });

  it('filters by severity', () => {
    const events = readEvents({ severity: 'critical' });
    expect(events).toHaveLength(1);
    expect(events[0].severity).toBe('critical');
  });

  it('filters by agent', () => {
    const events = readEvents({ agent: 'claude' });
    expect(events).toHaveLength(2);
    expect(events.every(e => e.agent === 'claude')).toBe(true);
  });

  it('filters by count', () => {
    const events = readEvents({ count: 2 });
    expect(events).toHaveLength(2);
    // Should be the 2 newest events
    expect(events[0].source).toBe('shield');
    expect(events[1].source).toBe('arp');
  });

  it('filters by category', () => {
    const events = readEvents({ category: 'scan' });
    expect(events).toHaveLength(2);
    expect(events.every(e => e.category === 'scan')).toBe(true);
  });
});

// ===========================================================================
// 4. readEvents since filter
// ===========================================================================

describe('readEvents since filter', () => {
  it('filters with relative "7d" -- returns only recent events', () => {
    // Write an event now (will have a current timestamp)
    writeEvent(makePartial({ action: 'recent' }));

    // Manually append an old event (30 days ago) to the JSONL file
    const eventsPath = getEventsPath();
    const oldTimestamp = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const oldEvent: ShieldEvent = {
      id: uuidv7(),
      timestamp: oldTimestamp,
      version: 1,
      source: 'shield',
      category: 'test',
      severity: 'info',
      agent: null,
      sessionId: null,
      action: 'old-action',
      target: 'old-target',
      outcome: 'monitored',
      detail: {},
      prevHash: 'fake',
      eventHash: 'fake',
      orgId: null,
      managed: false,
      agentId: null,
    };
    // Prepend so it appears earlier in the file (chronological order)
    const existing = fs.readFileSync(eventsPath, 'utf-8');
    fs.writeFileSync(eventsPath, JSON.stringify(oldEvent) + '\n' + existing);

    const all = readEvents();
    expect(all).toHaveLength(2);

    const recent = readEvents({ since: '7d' });
    expect(recent).toHaveLength(1);
    expect(recent[0].action).toBe('recent');
  });

  it('filters with ISO 8601 date string', () => {
    writeEvent(makePartial({ action: 'today' }));

    // Inject an old event directly into the file
    const eventsPath = getEventsPath();
    const twoWeeksAgo = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString();
    const oldEvent: ShieldEvent = {
      id: uuidv7(),
      timestamp: twoWeeksAgo,
      version: 1,
      source: 'shield',
      category: 'test',
      severity: 'info',
      agent: null,
      sessionId: null,
      action: 'old',
      target: 'old',
      outcome: 'monitored',
      detail: {},
      prevHash: 'fake',
      eventHash: 'fake',
      orgId: null,
      managed: false,
      agentId: null,
    };
    const existing = fs.readFileSync(eventsPath, 'utf-8');
    fs.writeFileSync(eventsPath, JSON.stringify(oldEvent) + '\n' + existing);

    // Filter since 7 days ago as ISO string
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const filtered = readEvents({ since: sevenDaysAgo });
    expect(filtered).toHaveLength(1);
    expect(filtered[0].action).toBe('today');
  });
});

// ===========================================================================
// 5. verifyEventChain
// ===========================================================================

describe('verifyEventChain', () => {
  it('returns valid for an empty array', () => {
    const result = verifyEventChain([]);
    expect(result).toEqual({ valid: true, brokenAt: null });
  });

  it('returns valid for a correct chain', () => {
    const e1 = writeEvent(makePartial({ action: 'a' }));
    const e2 = writeEvent(makePartial({ action: 'b' }));
    const e3 = writeEvent(makePartial({ action: 'c' }));

    // verifyEventChain expects chronological order (oldest-first)
    const result = verifyEventChain([e1, e2, e3]);
    expect(result).toEqual({ valid: true, brokenAt: null });
  });

  it('detects tampered eventHash', () => {
    const e1 = writeEvent(makePartial({ action: 'a' }));
    const e2 = writeEvent(makePartial({ action: 'b' }));

    // Tamper with the eventHash of the first event
    const tampered: ShieldEvent = { ...e1, eventHash: 'deadbeef'.repeat(8) };
    const result = verifyEventChain([tampered, e2]);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
  });

  it('detects broken prevHash link', () => {
    const e1 = writeEvent(makePartial({ action: 'a' }));
    const e2 = writeEvent(makePartial({ action: 'b' }));
    const e3 = writeEvent(makePartial({ action: 'c' }));

    // Break the chain: e2's prevHash no longer matches e1's eventHash
    const broken: ShieldEvent = { ...e2, prevHash: 'badc0ffee'.repeat(7) + 'badc0ffe' };
    // Recompute eventHash so only the prevHash link is broken, not the hash itself
    const { eventHash: _, ...rest } = broken;
    const recomputedHash = createHash('sha256').update(JSON.stringify(rest)).digest('hex');
    const brokenWithHash: ShieldEvent = { ...rest, eventHash: recomputedHash };

    const result = verifyEventChain([e1, brokenWithHash, e3]);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('detects wrong genesis hash on first event', () => {
    const e1 = writeEvent(makePartial({ action: 'a' }));

    // Replace prevHash with something other than the genesis hash
    const tampered: ShieldEvent = { ...e1, prevHash: 'not-the-genesis-hash' };
    const { eventHash: _, ...rest } = tampered;
    const recomputedHash = createHash('sha256').update(JSON.stringify(rest)).digest('hex');
    const tamperedWithHash: ShieldEvent = { ...rest, eventHash: recomputedHash };

    const result = verifyEventChain([tamperedWithHash]);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
  });
});

// ===========================================================================
// 6. Hash chain integrity (write -> read -> verify round-trip)
// ===========================================================================

describe('hash chain integrity', () => {
  it('write 3 events, read newest-first, reverse to chronological, verify valid', () => {
    writeEvent(makePartial({ action: 'x' }));
    writeEvent(makePartial({ action: 'y' }));
    writeEvent(makePartial({ action: 'z' }));

    const newestFirst = readEvents();
    expect(newestFirst).toHaveLength(3);

    // Reverse to chronological (oldest-first) for verification
    const chronological = [...newestFirst].reverse();
    const result = verifyEventChain(chronological);
    expect(result).toEqual({ valid: true, brokenAt: null });
  });

  it('first event in chain has genesis prevHash after round-trip', () => {
    writeEvent(makePartial({ action: 'only-one' }));
    const events = readEvents();
    expect(events).toHaveLength(1);
    expect(events[0].prevHash).toBe(GENESIS_HASH);
  });

  it('hash chain links are consistent across 5 events', () => {
    for (let i = 0; i < 5; i++) {
      writeEvent(makePartial({ action: `event-${i}` }));
    }

    const newestFirst = readEvents();
    const chronological = [...newestFirst].reverse();

    // Each event's prevHash should equal the prior event's eventHash
    for (let i = 1; i < chronological.length; i++) {
      expect(chronological[i].prevHash).toBe(chronological[i - 1].eventHash);
    }

    // Full chain verification
    const result = verifyEventChain(chronological);
    expect(result).toEqual({ valid: true, brokenAt: null });
  });
});

// ===========================================================================
// Directory helpers (supplementary)
// ===========================================================================

describe('getShieldDir / getEventsPath', () => {
  it('getShieldDir creates the directory under mocked homedir', () => {
    const dir = getShieldDir();
    expect(dir).toBe(path.join(tempDir, '.opena2a', 'shield'));
    expect(fs.existsSync(dir)).toBe(true);
  });

  it('getEventsPath returns path ending in events.jsonl', () => {
    const p = getEventsPath();
    expect(p).toBe(path.join(tempDir, '.opena2a', 'shield', 'events.jsonl'));
  });
});
