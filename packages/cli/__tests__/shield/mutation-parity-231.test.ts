/**
 * Mutation-parity tests for the external-authored half of PR #231.
 *
 * PR #231 landed three commits from two authors. Mutation testing was run on
 * the two written in-house (29 mutations, 29 killed) and never on the external
 * contributor's commit (e7e0909), which is 528 added lines in the
 * tamper-evidence path. Running it afterwards over the 161 production lines
 * that commit still owns left 21 genuine survivors. These tests kill the ones
 * that carry behaviour a user or an operator can observe.
 *
 * Each test names the mutation it kills so the pinning is not accidental: if a
 * later refactor makes one of these assertions vacuous, the mutation it names
 * comes back to life and this comment is the way to notice.
 *
 * Deliberately NOT pinned here, and why: nothing. The synthetic chain-break
 * event is a compile-time constant apart from `id`, `timestamp` and `detail`,
 * so its shape is asserted whole rather than field by field.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';

import type { ShieldEvent } from '../../src/shield/types.js';

// ---------------------------------------------------------------------------
// Mock node:os so homedir() resolves to a temp directory (same shape as
// chain-verified-review.test.ts).
// ---------------------------------------------------------------------------

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

const { writeEvent, readEvents, getEventsPath, GENESIS_HASH } =
  await import('../../src/shield/events.js');
const { runShieldPhase } = await import('../../src/commands/review.js');

let tempHome: string;
let targetDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'mp231-home-'));
  targetDir = fs.mkdtempSync(path.join(tmpdir(), 'mp231-target-'));
  _mockHomeDir = tempHome;
});

afterEach(() => {
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(targetDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

/**
 * Build a hash-valid chain with caller-chosen timestamps.
 *
 * `writeEvent` always stamps "now", so a genuinely-chained event older than the
 * review window cannot be produced through it. `verifyEventChain` recomputes
 * `sha256(JSON.stringify(event-minus-eventHash))` in key-insertion order, so
 * constructing the object here in that same order and appending `eventHash`
 * last reproduces exactly what it will check.
 */
function writeChain(specs: Array<Partial<ShieldEvent> & { timestamp: string }>): ShieldEvent[] {
  const out: ShieldEvent[] = [];
  let prevHash = GENESIS_HASH;

  for (const [i, spec] of specs.entries()) {
    const body = {
      id: `00000000-0000-7000-8000-${String(i).padStart(12, '0')}`,
      timestamp: spec.timestamp,
      version: 1 as const,
      source: spec.source ?? ('shield' as const),
      category: spec.category ?? 'posture-assessment',
      severity: spec.severity ?? ('info' as const),
      agent: spec.agent ?? null,
      sessionId: spec.sessionId ?? null,
      action: spec.action ?? 'test-action',
      target: spec.target ?? 'test-target',
      outcome: spec.outcome ?? ('allowed' as const),
      detail: spec.detail ?? {},
      prevHash,
      orgId: null,
      managed: false,
      agentId: null,
    };
    const event = { ...body, eventHash: sha256(JSON.stringify(body)) } as unknown as ShieldEvent;
    out.push(event);
    prevHash = event.eventHash;
  }

  const p = getEventsPath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, out.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf-8');
  return out;
}

const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();

/** Rewrite the log with `junk` spliced in between the existing lines. */
function spliceJunkLine(junk: string, at: number): void {
  const p = getEventsPath();
  const lines = fs.readFileSync(p, 'utf-8').split('\n').filter(l => l.trim().length > 0);
  lines.splice(at, 0, junk);
  fs.writeFileSync(p, lines.join('\n') + '\n', 'utf-8');
}

// ===========================================================================
// readAllEvents: the valid-JSON-but-not-an-object guard
// ===========================================================================

describe('readAllEvents non-object guard', () => {
  // The guard is `parsed === null || typeof parsed !== 'object' ||
  // Array.isArray(parsed)`. Only the `=== null` clause was pinned, so dropping
  // either of the other two clauses survived, as did turning the `continue`
  // into a `break`.
  //
  // This matters beyond tidiness: a non-object line that slips past the guard
  // is pushed as if it were an event, and every later chain check reads
  // `prevHash` off a number or an array. The chain then "breaks" on a log
  // nobody tampered with, which raises a critical finding on a clean project --
  // the same false-critical shape the concurrency lock in this PR exists to
  // remove.

  for (const [label, junk] of [
    ['a number', '123'],
    ['a string', '"not-an-event"'],
    ['a boolean', 'true'],
  ] as const) {
    it(`skips ${label} line and still reads the events after it (kills M03, M06)`, () => {
      writeEvent({
        source: 'shield', category: 'posture-assessment', severity: 'info',
        agent: null, sessionId: null, action: 'a', target: 't',
        outcome: 'allowed', detail: {}, orgId: null, managed: false, agentId: null,
      });
      writeEvent({
        source: 'shield', category: 'posture-assessment', severity: 'info',
        agent: null, sessionId: null, action: 'b', target: 't',
        outcome: 'allowed', detail: {}, orgId: null, managed: false, agentId: null,
      });

      // Junk in the MIDDLE: a `break` here would drop the trailing genuine
      // event, a `continue` keeps it. That distinction is the point.
      spliceJunkLine(junk, 1);

      const events = readEvents();

      expect(events).toHaveLength(2);
      // Nothing that is not an object may reach the caller.
      for (const e of events) {
        expect(typeof e).toBe('object');
        expect(e).not.toBeNull();
        expect(Array.isArray(e)).toBe(false);
      }
      expect(events.map(e => e.action).sort()).toEqual(['a', 'b']);
    });
  }

  it('skips an array line and still reads the events after it (kills M04, M06)', () => {
    writeEvent({
      source: 'shield', category: 'posture-assessment', severity: 'info',
      agent: null, sessionId: null, action: 'a', target: 't',
      outcome: 'allowed', detail: {}, orgId: null, managed: false, agentId: null,
    });
    writeEvent({
      source: 'shield', category: 'posture-assessment', severity: 'info',
      agent: null, sessionId: null, action: 'b', target: 't',
      outcome: 'allowed', detail: {}, orgId: null, managed: false, agentId: null,
    });

    spliceJunkLine('[{"id":"not-an-event"}]', 1);

    const events = readEvents();

    expect(events).toHaveLength(2);
    for (const e of events) expect(Array.isArray(e)).toBe(false);
    expect(events.map(e => e.action).sort()).toEqual(['a', 'b']);
  });
});

// ===========================================================================
// runShieldPhase: the 7d review window
// ===========================================================================

describe('runShieldPhase review window', () => {
  it('counts only events inside the 7d window (kills M26, M27)', () => {
    // Both events are genuinely chained, so nothing here is excluded for
    // tamper reasons -- the only thing that can drop the old one is the window.
    writeChain([
      { timestamp: daysAgo(30), action: 'ancient' },
      { timestamp: daysAgo(1), action: 'recent' },
    ]);

    const data = runShieldPhase(targetDir);

    expect(data.chainBroken).toBe(false);
    expect(data.eventCount).toBe(1);
  });

  it('keeps an event just inside the window', () => {
    writeChain([
      { timestamp: daysAgo(6), action: 'just-inside' },
      { timestamp: daysAgo(1), action: 'recent' },
    ]);

    expect(runShieldPhase(targetDir).eventCount).toBe(2);
  });
});

// ===========================================================================
// runShieldPhase: ARP stats are scoped to arp events
// ===========================================================================

describe('runShieldPhase ARP stats', () => {
  it('aggregates only source=arp events, and not just the first (kills M52, M53)', () => {
    // review.ts recomputes getARPStats' semantics inline over the verified
    // window: `events.filter(e => e.source === 'arp').slice(0, 10000)`. Neither
    // the source filter nor the cap was pinned on that path, although the
    // equivalent cap inside getARPStats itself was.
    writeChain([
      { timestamp: daysAgo(1), source: 'arp' as ShieldEvent['source'], category: 'process.spawn', action: 'arp-1' },
      { timestamp: daysAgo(1), source: 'arp' as ShieldEvent['source'], category: 'process.spawn', action: 'arp-2' },
      { timestamp: daysAgo(1), source: 'shield' as ShieldEvent['source'], category: 'posture-assessment', action: 'not-arp' },
    ]);

    const data = runShieldPhase(targetDir);

    expect(data.chainBroken).toBe(false);
    expect(data.eventCount).toBe(3);
    // 2, not 3 (source filter) and not 1 (count cap must not truncate).
    expect(data.arpStats.totalEvents).toBe(2);
  });
});

// ===========================================================================
// runShieldPhase: the synthetic chain-break event
// ===========================================================================

describe('synthetic chain-break event', () => {
  /** A valid two-event chain plus a forged third line that does not chain on. */
  function brokenLog(): void {
    writeChain([
      { timestamp: daysAgo(1), action: 'genuine-1' },
      { timestamp: daysAgo(1), action: 'genuine-2' },
    ]);
    const forged = {
      id: '00000000-0000-7000-8000-0000000000ff',
      timestamp: daysAgo(1),
      version: 1,
      source: 'shield',
      category: 'posture-assessment',
      severity: 'info',
      agent: null,
      sessionId: null,
      action: 'forged',
      target: 'test-target',
      outcome: 'allowed',
      detail: {},
      prevHash: 'f0'.repeat(32),
      orgId: null,
      managed: false,
      agentId: null,
      eventHash: '0f'.repeat(32),
    };
    fs.appendFileSync(getEventsPath(), JSON.stringify(forged) + '\n', 'utf-8');
  }

  it('carries the break index and a reason a human can act on (kills M43, M45)', () => {
    brokenLog();

    const data = runShieldPhase(targetDir);
    expect(data.chainBroken).toBe(true);
    expect(data.brokenAt).toBe(2);

    const int002 = data.classifiedFindings.find(f => f.finding.id === 'SHIELD-INT-002');
    expect(int002).toBeDefined();

    const synthetic = int002!.examples.find(e => e.action === 'event-chain-break');
    expect(synthetic).toBeDefined();

    const detail = synthetic!.detail as Record<string, unknown>;
    // The forensic payload: WHERE it broke and HOW MUCH was dropped. Hardcoding
    // either turns the finding into a rumour.
    expect(detail.brokenAt).toBe(2);
    expect(detail.untrustedEventsExcluded).toBe(1);
    expect(String(detail.reason)).toContain('hash chain break');
    expect(String(detail.reason)).toContain('excluded');
  });

  it('is stamped now, not at the epoch, and carries a unique id (kills M32, M33)', () => {
    brokenLog();

    const before = Date.now();
    const data = runShieldPhase(targetDir);
    const after = Date.now();

    const synthetic = data.classifiedFindings
      .find(f => f.finding.id === 'SHIELD-INT-002')!
      .examples.find(e => e.action === 'event-chain-break')!;

    const ts = Date.parse(synthetic.timestamp);
    expect(Number.isNaN(ts)).toBe(false);
    // An epoch timestamp renders as 1970 in the report and sorts to the top of
    // every timeline.
    expect(ts).toBeGreaterThanOrEqual(before - 1000);
    expect(ts).toBeLessThanOrEqual(after + 1000);

    expect(synthetic.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );

    // Two runs of the same broken log must not reuse one id.
    const second = runShieldPhase(targetDir).classifiedFindings
      .find(f => f.finding.id === 'SHIELD-INT-002')!
      .examples.find(e => e.action === 'event-chain-break')!;
    expect(second.id).not.toBe(synthetic.id);
  });

  it('has the exact shape the classifier and the report expect (kills M38, M39, M41, M42, M46-M50)', () => {
    brokenLog();

    const synthetic = runShieldPhase(targetDir).classifiedFindings
      .find(f => f.finding.id === 'SHIELD-INT-002')!
      .examples.find(e => e.action === 'event-chain-break')!;

    // `id`, `timestamp` and `detail` vary per run and are asserted above.
    const { id: _id, timestamp: _ts, detail: _detail, ...shape } = synthetic;

    expect(shape).toEqual({
      version: 1,
      source: 'shield',
      category: 'integrity',
      severity: 'critical',
      agent: null,
      sessionId: null,
      action: 'event-chain-break',
      target: 'events.jsonl',
      outcome: 'blocked',
      // Empty because this event is synthesised in memory and never written to
      // the log: it is not a link in the chain and must not look like one.
      prevHash: '',
      eventHash: '',
      orgId: null,
      managed: false,
      agentId: null,
    });
  });
});
