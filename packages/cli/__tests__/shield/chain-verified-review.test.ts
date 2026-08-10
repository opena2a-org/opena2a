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
const { runShieldPhase, shieldCompositeScore, shieldRiskFloorScore } =
  await import('../../src/commands/review.js');

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
    expect(result.untrusted).toEqual([]);
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
    // The untrusted tail is returned separately (newest-first) so a caller can
    // count it for scoring — never so it can be classified into findings.
    expect(result.untrusted.map(e => e.action)).toEqual(['forged-2', 'forged-1']);
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
    expect(brokenPhase.shieldPostureScore).toBe(Math.max(0, cleanPhase.shieldPostureScore - 15));
  });
});

// ===========================================================================
// C1 — a chain break must never score better than the same log unbroken
//
// The exclusion is the right defense against forging INTO the log, but on its
// own it hands an append-only adversary a cheaper attack: corrupt one line and
// every genuine finding written after it disappears from classification, so
// the phase score IMPROVES. Blinding the sensor must not beat forging into it.
//
// Each case builds the SAME event content under two temp HOMEs — one intact,
// one with a single unparseable line inserted after the first event — and
// compares. Two HOMEs against one targetDir means any ambient baseline
// (active tools, policy, shell integration) is identical on both sides and
// cancels out of the comparison.
// ===========================================================================

describe('chain-break score floor (C1)', () => {
  type Partial_ = Record<string, unknown>;

  /** Benign prefix event: classifies to nothing, keeps the trusted slice non-empty. */
  const PREFIX: Partial_ = { action: 'baseline', category: 'posture-assessment' };

  /**
   * A genuine tail whose findings include a critical:
   * SHIELD-INT-001 (critical) + SHIELD-PROC-001 (high) + SHIELD-PROC-002
   * (medium) + SHIELD-BAS-001 (medium).
   */
  function criticalTail(dir: string): Partial_[] {
    return [
      {
        source: 'configguard', outcome: 'blocked', action: 'tamper-detected',
        target: path.join(dir, 'mcp.json'),
      },
      { source: 'arp', category: 'process.spawn', action: 'spawn', target: '/usr/bin/curl' },
      { source: 'arp', category: 'network.connect', action: 'connect', target: '203.0.113.7' },
      { source: 'arp', category: 'anomaly', action: 'anomaly', target: 'agent-x' },
    ];
  }

  /** A genuine tail whose findings are high at worst: SHIELD-PROC-001 only. */
  function highOnlyTail(): Partial_[] {
    return [
      { source: 'arp', category: 'process.spawn', action: 'spawn', target: '/usr/bin/curl' },
    ];
  }

  /**
   * Write `tail` into a fresh HOME, optionally breaking the chain first.
   *
   * The break vector is one unparseable line, which is what an append-only
   * adversary can produce without knowing the chain hashes: writeEvent reads
   * the last line to derive prevHash, fails to parse the junk, and falls back
   * to the genesis hash — so every event after it fails verification.
   */
  function buildLog(home: string, tail: Partial_[], breakChain: boolean): void {
    _mockHomeDir = home;
    getShieldDir();
    writeEvent(makePartial(PREFIX));
    if (breakChain) fs.appendFileSync(getEventsPath(), 'not json at all\n', 'utf-8');
    for (const t of tail) writeEvent(makePartial(t));
  }

  let intactHome: string;
  let brokenHome: string;
  let emptyHome: string;

  beforeEach(() => {
    intactHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-chain-floor-intact-'));
    brokenHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-chain-floor-broken-'));
    emptyHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-chain-floor-empty-'));
  });

  afterEach(() => {
    for (const d of [intactHome, brokenHome, emptyHome]) {
      fs.rmSync(d, { recursive: true, force: true });
    }
  });

  /** Run the phase against `home` with the shared targetDir. */
  function phaseFor(home: string) {
    _mockHomeDir = home;
    return runShieldPhase(targetDir);
  }

  it('(i) a break in front of a critical tail scores no better than the intact chain', () => {
    const tail = criticalTail(targetDir);
    buildLog(intactHome, tail, false);
    buildLog(brokenHome, tail, true);

    const intact = phaseFor(intactHome);
    const broken = phaseFor(brokenHome);

    // Non-vacuity: the fixture really does break, really does exclude the
    // whole genuine tail, and the intact side really does carry the findings
    // the break would otherwise hide.
    expect(intact.chainBroken).toBe(false);
    expect(broken.chainBroken).toBe(true);
    expect(broken.untrustedEventsExcluded).toBe(tail.length);
    expect(findingIds(intact.classifiedFindings)).toEqual(
      expect.arrayContaining(['SHIELD-INT-001', 'SHIELD-PROC-001', 'SHIELD-PROC-002', 'SHIELD-BAS-001']),
    );

    // Both scoring layers. The phase posture is what a terminal user reads;
    // shieldCompositeScore is the composite INPUT, where the reward was larger
    // and was masked in the final composite only because the synthetic break
    // critical happens to pin the risk floor. Masking is incidental to the
    // fixture, so both layers are pinned rather than just the visible one.
    expect(broken.shieldPostureScore).toBeLessThanOrEqual(intact.shieldPostureScore);
    expect(shieldCompositeScore(broken)).toBeLessThanOrEqual(shieldCompositeScore(intact));
    expect(shieldRiskFloorScore(broken).score).toBeLessThanOrEqual(shieldRiskFloorScore(intact).score);
  });

  it('(i) the excluded tail lowers the score without ever being reported', () => {
    // The floor is computed from untrusted events, which must stay out of
    // every reported surface. Trusting their content would readmit the exact
    // forgery vectors the exclusion exists to close.
    const tail = criticalTail(targetDir);
    buildLog(brokenHome, tail, true);

    const broken = phaseFor(brokenHome);
    const ids = findingIds(broken.classifiedFindings);

    expect(ids).toEqual(['SHIELD-INT-002']);
    expect(broken.classifiedFindings[0].count).toBe(1);
    for (const hidden of ['SHIELD-INT-001', 'SHIELD-PROC-001', 'SHIELD-PROC-002', 'SHIELD-BAS-001']) {
      expect(ids).not.toContain(hidden);
    }
    // ...yet the counterfactual counts saw them, which is what floors the score.
    expect(broken.preExclusionCounts).toEqual({ critical: 1, high: 1, medium: 2 });
  });

  it('(ii) a break in front of a highs-only tail is still no better, and is not over-penalized', () => {
    // Regression guard against "fixing" C1 with a fixed penalty. Here the
    // break already scored WORSE than the intact chain before any fix (one
    // critical costs more than one high), so a penalty stacked on top would
    // be invisible to the inequality alone. Pinning the exact value catches it.
    const tail = highOnlyTail();
    buildLog(intactHome, tail, false);
    buildLog(brokenHome, tail, true);

    const intact = phaseFor(intactHome);
    const broken = phaseFor(brokenHome);
    // Ambient baseline with no events at all: the posture before any penalty.
    const baseline = phaseFor(emptyHome).shieldPostureScore;

    expect(broken.chainBroken).toBe(true);
    expect(findingIds(intact.classifiedFindings)).toEqual(['SHIELD-PROC-001']);

    expect(broken.shieldPostureScore).toBeLessThanOrEqual(intact.shieldPostureScore);
    expect(shieldCompositeScore(broken)).toBeLessThanOrEqual(shieldCompositeScore(intact));

    // Exactly one critical's worth of penalty — the chain-break finding — and
    // no more. The floor took the harsher of the two views; it did not add them.
    expect(broken.shieldPostureScore).toBe(Math.max(0, baseline - 15));
    expect(shieldCompositeScore(broken)).toBe(90 - 30);
  });

  it('an intact chain carries no counterfactual counts and is scored unchanged', () => {
    // The floor must be inert when there is nothing to floor: no
    // preExclusionCounts, and the composite is the plain finding arithmetic.
    buildLog(intactHome, criticalTail(targetDir), false);
    const intact = phaseFor(intactHome);

    expect(intact.preExclusionCounts).toBeUndefined();
    expect(intact.untrustedEventsExcluded).toBe(0);
    expect(intact.brokenAt).toBeNull();
    // 90 - 30(critical) - 15(high) - 6*2(medium)
    expect(shieldCompositeScore(intact)).toBe(33);
  });
});
