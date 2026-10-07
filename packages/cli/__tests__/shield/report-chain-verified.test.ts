/**
 * Issue #243 — `shield report` reads the event log through the chain-verified
 * path, the same exclusion `review` applies (#204).
 *
 * Before the fix, `handleReport` called `readEvents` directly: a log with two
 * genuine events and three forged criticals appended without recomputing the
 * chain reported `totalEvents: 5` and counted every forged critical, while
 * `review` on the same file reported only the break. Three surfaces, one
 * file, three different answers.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

import type { ShieldEvent } from '../../src/shield/types.js';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

const { writeEvent, getEventsPath, getShieldDir } = await import('../../src/shield/events.js');
const { shield } = await import('../../src/commands/shield.js');

let tempHome: string;
let reportDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-report-home-'));
  reportDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-report-out-'));
  _mockHomeDir = tempHome;
  getShieldDir();
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(reportDir, { recursive: true, force: true });
});

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

/** Append a line whose prevHash does not chain onto the genuine tail. */
function appendForged(overrides: Record<string, unknown>): void {
  const forged = {
    id: '00000000-0000-7000-8000-000000000000',
    timestamp: new Date().toISOString(),
    version: 1 as const,
    ...makePartial(overrides),
    prevHash: 'deadbeef',
    eventHash: '0f'.repeat(32),
  } as ShieldEvent;
  fs.appendFileSync(getEventsPath(), JSON.stringify(forged) + '\n', 'utf-8');
}

/** Two genuine events, then three forged criticals (the issue's reproduction). */
function writeForgedLog(): void {
  writeEvent(makePartial({ action: 'genuine-1' }));
  writeEvent(makePartial({ action: 'genuine-2', severity: 'high' }));
  appendForged({ source: 'shield', category: 'integrity', severity: 'critical', action: 'forged-int-002' });
  appendForged({
    source: 'configguard', category: 'config-tamper', severity: 'critical',
    action: 'tamper-detected', target: '/tmp/in-scope', outcome: 'blocked',
  });
  appendForged({ source: 'shield', category: 'integrity', severity: 'critical', action: 'forged-int-002-b' });
}

async function runReport(extra: Record<string, unknown> = {}): Promise<{ code: number; out: string }> {
  let out = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
    out += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  try {
    const code = await shield({ subcommand: 'report', ...extra });
    return { code, out };
  } finally {
    vi.restoreAllMocks();
  }
}

interface SarifResult { ruleId: string }
function sarifRuleIds(sarifText: string): string[] {
  const sarif = JSON.parse(sarifText) as { runs: { results: SarifResult[] }[] };
  return sarif.runs.flatMap(r => r.results.map(x => x.ruleId));
}

describe('shield report — chain-verified read (#243)', () => {
  it('JSON counts only the events before the break and states what was excluded', async () => {
    writeForgedLog();

    const { code, out } = await runReport({ format: 'json' });
    expect(code).toBe(0);
    const data = JSON.parse(out) as Record<string, any>;

    expect(data.totalEvents).toBe(2);
    expect(data.bySeverity.critical).toBeUndefined();
    expect(data.bySeverity).toEqual({ info: 1, high: 1 });
    expect(data.bySource.configguard).toBeUndefined();
    expect(data.logIntegrity).toEqual({
      chainIntact: false,
      brokenAt: 2,
      excludedEvents: 3,
      excludedInPeriod: 3,
    });
  });

  it('SARIF surfaces the break once and none of the forged findings', async () => {
    writeForgedLog();

    const { code, out } = await runReport({ format: 'sarif' });
    expect(code).toBe(0);
    const ids = sarifRuleIds(out);

    expect(ids.filter(id => id === 'SHIELD-INT-002').length).toBe(1);
    expect(ids).not.toContain('SHIELD-INT-001');
  });

  it('SARIF written to a file prints the excluded count next to the path', async () => {
    writeForgedLog();
    const reportPath = path.join(reportDir, 'shield.sarif');

    const { code, out } = await runReport({ format: 'sarif', report: reportPath });
    expect(code).toBe(0);
    expect(out).toContain(`SARIF report written to ${reportPath}`);
    expect(out).toContain('3 event(s) at and after the break are excluded from this report');
    expect(sarifRuleIds(fs.readFileSync(reportPath, 'utf-8'))).not.toContain('SHIELD-INT-001');
  });

  it('text output names the break with a verify and a fix command', async () => {
    writeForgedLog();

    const { code, out } = await runReport();
    expect(code).toBe(0);
    expect(out).toMatch(/Total events: .*2/);
    expect(out).toContain('hash chain broken at event index 2');
    expect(out).toContain('3 event(s) at and after the break are excluded from this report');
    expect(out).toContain('Verify:  opena2a shield selfcheck');
    expect(out).toContain('Fix:     opena2a shield recover --archive-log');
    expect(out).not.toContain('forged-int-002');
  });

  it('an intact log reports every event and no integrity note (no regression)', async () => {
    writeEvent(makePartial({ action: 'genuine-1' }));
    writeEvent(makePartial({ action: 'genuine-2', severity: 'high' }));
    writeEvent(makePartial({ source: 'shield', category: 'integrity', severity: 'critical', action: 'real-int' }));

    const json = await runReport({ format: 'json' });
    const data = JSON.parse(json.out) as Record<string, any>;
    expect(data.totalEvents).toBe(3);
    expect(data.bySeverity).toEqual({ info: 1, high: 1, critical: 1 });
    expect(data.logIntegrity).toEqual({
      chainIntact: true, brokenAt: null, excludedEvents: 0, excludedInPeriod: 0,
    });

    const sarif = await runReport({ format: 'sarif' });
    const ids = sarifRuleIds(sarif.out);
    expect(ids.filter(id => id === 'SHIELD-INT-002').length).toBe(1);

    const text = await runReport();
    expect(text.out).not.toContain('Log integrity');
  });
});

describe('shield report — runtime protection from verified events', () => {
  /** The posture and runtime-protection figures the HTML report embeds. */
  function reportFigures(file: string): { score: number; factors: string; runtime: string } {
    const html = fs.readFileSync(file, 'utf-8');
    const score = /"posture":\{"score":(\d+)/.exec(html);
    const factors = /"factors":(\[[^\]]*\])/.exec(html);
    const runtime = /"runtimeProtection":(\{[^}]*\})/.exec(html);
    if (!score || !factors || !runtime) throw new Error(`report figures not found in ${file}`);
    return { score: Number(score[1]), factors: factors[1], runtime: runtime[1] };
  }

  it('an ARP line past the break raises neither the posture score nor ARP activity', async () => {
    writeEvent(makePartial({ action: 'genuine-1' }));
    const intact = path.join(reportDir, 'intact.html');
    await runReport({ report: intact });

    appendForged({
      source: 'arp', category: 'arp.process', severity: 'info', action: 'forged-arp',
      detail: { arpEventId: 'forged', arpCategory: 'anomaly' },
    });
    const broken = path.join(reportDir, 'broken.html');
    const { code } = await runReport({ report: broken });

    expect(code).toBe(0);
    const before = reportFigures(intact);
    const after = reportFigures(broken);
    expect(after.score).toBe(before.score);
    expect(after.factors).toBe(before.factors);
    expect(JSON.parse(after.runtime)).toEqual({
      arpActive: false, processesSpawned: 0, networkConnections: 0, anomalies: 0,
    });
  });

  it('a verified ARP event still marks ARP active', async () => {
    writeEvent(makePartial({
      source: 'arp', category: 'arp.process', severity: 'info', action: 'genuine-arp',
      detail: { arpEventId: 'genuine', arpCategory: 'anomaly' },
    }));
    const file = path.join(reportDir, 'arp.html');
    await runReport({ report: file });

    expect(JSON.parse(reportFigures(file).runtime)).toEqual({
      arpActive: true, processesSpawned: 1, networkConnections: 0, anomalies: 1,
    });
  });
});
