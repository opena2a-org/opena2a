/**
 * Issue #204 — verify the event hash chain at review time and exclude
 * events at or after the first chain break from classification.
 *
 * Acceptance criteria covered:
 *   1. Forged events appended after a genuine tail do NOT classify into
 *      findings; only the single chain-break finding is surfaced.
 *   2. A forged source:'shield' integrity-critical event past a break does
 *      not produce its own SHIELD-INT-002.
 *   3. A forged in-scope-absolute-target configguard event past a break
 *      does not produce SHIELD-INT-001.
 *   4. Genuine, unbroken event streams classify exactly as before.
 *
 * All tests are deterministic and file-based — no spawns, no fixtures
 * outside the temp dirs created here.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';

import type { ShieldEvent } from '../../src/shield/types.js';

// ---------------------------------------------------------------------------
// Mock node:os so that homedir() returns our temp directory.
// ---------------------------------------------------------------------------

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => _mockHomeDir,
  };
});

// Import after mocks so the modules pick up the mocked homedir.
const { writeEvent, readEvents, readVerifiedEvents, getShieldDir, getEventsPath } =
  await import('../../src/shield/events.js');
const { classifyEvents, filterEventsToTarget } =
  await import('../../src/shield/findings.js');
const { runShieldPhase } = await import('../../src/commands/review.js');

// ---------------------------------------------------------------------------
// Temp directory setup
// ---------------------------------------------------------------------------

let tempHome: string;
let targetDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-chain-review-home-'));
  targetDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-chain-review-target-'));
  _mockHomeDir = tempHome;
});

afterEach(() => {
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(targetDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makePartial(overrides: Record<string, unknown> = {}) {
  return {
    source: 'shield' as const,
    category: 'posture-assessment',
    severity: 'info' as const,
    agent: null,
    sessionId: null,
    action: 'test-action',
    target: 'test-target',
    outcome: 'allowed' as const,
    detail: {},
    orgId: null,
    managed: false,
    agentId: null,
    ...overrides,
  };
}

/**
 * Append a forged event directly to events.jsonl, bypassing writeEvent.
 * The forged line carries hash fields that do not chain onto the genuine
 * tail — exactly what an attacker without the genuine tail hashes writes.
 */
function appendForgedEvent(overrides: Record<string, unknown> = {}): ShieldEvent {
  const forged = {
    id: '00000000-0000-7000-8000-000000000000',
    timestamp: new Date().toISOString(),
    version: 1 as const,
    ...makePartial(),
    prevHash: 'f0'.repeat(32),
    eventHash: '0f'.repeat(32),
    ...overrides,
  } as ShieldEvent;
  fs.appendFileSync(getEventsPath(), JSON.stringify(forged) + '\n', 'utf-8');
  return forged;
}

function findingIds(findings: { finding: { id: string } }[]): string[] {
  return findings.map(f => f.finding.id);
}

// ===========================================================================
// readVerifiedEvents
// ===========================================================================

describe('readVerifiedEvents', () => {
  it('returns all events with chainBroken=false for a genuine stream', () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'first' }));
    writeEvent(makePartial({ action: 'second' }));
    writeEvent(makePartial({ action: 'third' }));

    const result = readVerifiedEvents();
    expect(result.chainBroken).toBe(false);
    expect(result.brokenAt).toBeNull();
    expect(result.untrustedCount).toBe(0);
    expect(result.firstUntrusted).toBeNull();
    expect(result.events).toEqual(readEvents());
  });

  it('is trivially valid on a missing events file', () => {
    const result = readVerifiedEvents();
    expect(result.chainBroken).toBe(false);
    expect(result.events).toEqual([]);
  });

  it('excludes forged events appended after a genuine tail', () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine-1' }));
    writeEvent(makePartial({ action: 'genuine-2' }));
    appendForgedEvent({ action: 'forged-1' });
    appendForgedEvent({ action: 'forged-2' });

    const result = readVerifiedEvents();
    expect(result.chainBroken).toBe(true);
    expect(result.brokenAt).toBe(2);
    expect(result.untrustedCount).toBe(2);
    expect(result.firstUntrusted?.action).toBe('forged-1');
    expect(result.events.map(e => e.action)).toEqual(['genuine-2', 'genuine-1']);
  });

  it('excludes everything at and after a tampered middle event', () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'first' }));
    writeEvent(makePartial({ action: 'second' }));
    writeEvent(makePartial({ action: 'third' }));

    // Tamper with the second event's content in place: its eventHash no
    // longer matches, so the chain breaks at index 1.
    const eventsPath = getEventsPath();
    const lines = fs.readFileSync(eventsPath, 'utf-8').trim().split('\n');
    const second = JSON.parse(lines[1]) as ShieldEvent;
    second.action = 'tampered';
    lines[1] = JSON.stringify(second);
    fs.writeFileSync(eventsPath, lines.join('\n') + '\n', 'utf-8');

    const result = readVerifiedEvents();
    expect(result.chainBroken).toBe(true);
    expect(result.brokenAt).toBe(1);
    expect(result.untrustedCount).toBe(2);
    expect(result.events.map(e => e.action)).toEqual(['first']);
  });

  it('treats a fully forged log (break at index 0) as having no trusted events', () => {
    getShieldDir();
    appendForgedEvent({ action: 'forged-genesis' });

    const result = readVerifiedEvents();
    expect(result.chainBroken).toBe(true);
    expect(result.brokenAt).toBe(0);
    expect(result.events).toEqual([]);
  });

  it('applies filters to the trusted prefix only', () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine', severity: 'critical' }));
    appendForgedEvent({ action: 'forged', severity: 'critical' });

    const result = readVerifiedEvents({ severity: 'critical' });
    expect(result.events.map(e => e.action)).toEqual(['genuine']);
  });

  it('a literal `null` line is skipped like any corrupted line, not crashed on', () => {
    // Regression: `null` is valid JSON, so it used to reach
    // verifyEventChain, throw on property access, and silently empty the
    // whole shield phase — suppressing genuine findings.
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine-1' }));
    writeEvent(makePartial({ action: 'genuine-2' }));
    fs.appendFileSync(getEventsPath(), 'null\n', 'utf-8');

    const result = readVerifiedEvents();
    expect(result.chainBroken).toBe(false);
    expect(result.events.map(e => e.action)).toEqual(['genuine-2', 'genuine-1']);
  });

  it('KNOWN LIMITATION: a forged tail with correctly recomputed keyless hashes is trusted', () => {
    // The chain is keyless SHA-256 (see the GUARANTEE BOUNDARY note on
    // readVerifiedEvents): an attacker with write access who recomputes
    // eventHash/prevHash with the public algorithm produces a chain that
    // verifies. This test pins the gap so it stays documented rather than
    // implied-closed; closing it needs a keyed MAC or external anchor.
    getShieldDir();
    const genuine = writeEvent(makePartial({ action: 'genuine' }));

    const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
    const forged: Omit<ShieldEvent, 'eventHash'> = {
      id: '00000000-0000-7000-8000-000000000002',
      timestamp: new Date().toISOString(),
      version: 1,
      ...makePartial({ source: 'shield', category: 'integrity', severity: 'critical', action: 'forged-but-chained' }),
      prevHash: genuine.eventHash,
    } as Omit<ShieldEvent, 'eventHash'>;
    const chained: ShieldEvent = { ...forged, eventHash: sha256(JSON.stringify(forged)) };
    fs.appendFileSync(getEventsPath(), JSON.stringify(chained) + '\n', 'utf-8');

    const result = readVerifiedEvents();
    expect(result.chainBroken).toBe(false);
    expect(result.events.map(e => e.action)).toContain('forged-but-chained');
  });
});

// ===========================================================================
// runShieldPhase — acceptance criteria for #204
// ===========================================================================

describe('runShieldPhase chain verification (issue #204)', () => {
  it('AC1+AC2: forged shield integrity-critical events past a break surface only the single chain-break SHIELD-INT-002', () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine-1' }));
    writeEvent(makePartial({ action: 'genuine-2' }));

    // Forge the exact SHIELD-INT-002 manufacture vector, twice.
    appendForgedEvent({
      source: 'shield', category: 'integrity', severity: 'critical',
      action: 'forged-integrity-1',
    });
    appendForgedEvent({
      source: 'shield', category: 'integrity', severity: 'critical',
      action: 'forged-integrity-2',
    });

    const phase = runShieldPhase(targetDir);
    const int002 = phase.classifiedFindings.filter(f => f.finding.id === 'SHIELD-INT-002');

    // Exactly one SHIELD-INT-002 entry, with count 1 — the chain-break
    // finding itself, not one per forged event.
    expect(int002).toHaveLength(1);
    expect(int002[0].count).toBe(1);
    expect(int002[0].examples).toHaveLength(1);
    expect(int002[0].examples[0].action).toBe('event-chain-break');
    expect(int002[0].examples[0].detail.untrustedEventsExcluded).toBe(2);
  });

  it('AC3: a forged in-scope absolute-target configguard event past a break does not produce SHIELD-INT-001', () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine-1' }));

    // Forge the SHIELD-INT-001 manufacture vector that survives the
    // Option-1 path filter: configguard source, blocked outcome, and an
    // absolute target that IS inside the scanned directory.
    appendForgedEvent({
      source: 'configguard',
      outcome: 'blocked',
      target: path.join(targetDir, 'claude_desktop_config.json'),
      action: 'forged-tamper',
    });

    const phase = runShieldPhase(targetDir);
    const ids = findingIds(phase.classifiedFindings);

    expect(ids).not.toContain('SHIELD-INT-001');
    // The break itself is still surfaced, once.
    expect(ids.filter(id => id === 'SHIELD-INT-002')).toHaveLength(1);
  });

  it('AC4: a genuine, unbroken stream classifies exactly as before, with no chain-break finding', () => {
    getShieldDir();
    // A genuine configguard tamper event inside the target dir must still
    // classify to SHIELD-INT-001 (no regression from chain verification).
    writeEvent(makePartial({
      source: 'configguard',
      outcome: 'blocked',
      target: path.join(targetDir, 'mcp.json'),
      action: 'tamper-detected',
    }));
    writeEvent(makePartial({ action: 'diagnostic' }));

    const phase = runShieldPhase(targetDir);

    // Same result the pre-#204 pipeline computes on the same log.
    const before = classifyEvents(filterEventsToTarget(readEvents({ since: '7d' }), targetDir));
    expect(
      phase.classifiedFindings.map(f => ({ id: f.finding.id, count: f.count })),
    ).toEqual(
      before.map(f => ({ id: f.finding.id, count: f.count })),
    );

    expect(findingIds(phase.classifiedFindings)).toContain('SHIELD-INT-001');
    expect(findingIds(phase.classifiedFindings)).not.toContain('SHIELD-INT-002');
  });

  it('excluded forged events do not inflate eventCount', () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine-1' }));
    appendForgedEvent({ action: 'forged-1' });
    appendForgedEvent({ action: 'forged-2' });

    const phase = runShieldPhase(targetDir);
    expect(phase.eventCount).toBe(1);
  });

  it('chain break lowers the posture score by one critical, not one per forged event', () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine-1' }));

    const cleanPhase = runShieldPhase(targetDir);

    // Five forged integrity criticals — pre-#204 each would classify and
    // the composite would crater; now they cost exactly one critical.
    for (let i = 0; i < 5; i++) {
      appendForgedEvent({
        source: 'shield', category: 'integrity', severity: 'critical',
        action: `forged-${i}`,
      });
    }

    const brokenPhase = runShieldPhase(targetDir);
    expect(brokenPhase.postureScore).toBe(Math.max(0, cleanPhase.postureScore - 15));
  });
});
