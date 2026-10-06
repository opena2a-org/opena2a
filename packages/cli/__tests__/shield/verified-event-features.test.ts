/**
 * suggest, explain, triage and monitor read the event log through the
 * chain-verified reader.
 *
 * Each of them used to read the raw log, so a line appended without
 * recomputing the hash chain reached the LLM prompt, the policy suggestion,
 * the incident triage and the ARP import as if it were a recorded event.
 * Now an event at or after a chain break is never sent to the LLM or
 * counted, every output carries the log's verification status, and explain
 * labels each event it lists as verified or not.
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

// The LLM is stood in for, so the test sees exactly what each feature hands it.
vi.mock('../../src/shield/llm.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/shield/llm.js')>();
  return {
    ...actual,
    checkLlmAvailable: vi.fn(async () => ({ backend: 'local' })),
    suggestPolicy: vi.fn(async (agent: string, summary: { totalActions: number; totalSessions: number }) => ({
      agent,
      rules: {},
      reasoning: 'stand-in',
      confidence: 0.5,
      basedOnActions: summary.totalActions,
      basedOnSessions: summary.totalSessions,
    })),
    explainAnomaly: vi.fn(async (event: ShieldEvent) => ({
      eventId: event.id,
      severity: event.severity,
      explanation: 'stand-in',
      riskFactors: [],
      suggestedAction: 'investigate',
    })),
    triageIncident: vi.fn(async (events: ShieldEvent[]) => ({
      eventIds: events.map(e => e.id),
      classification: 'suspicious',
      severity: 'high',
      explanation: 'stand-in',
      responseSteps: [],
    })),
  };
});

const { writeEvent, getEventsPath, getShieldDir } = await import('../../src/shield/events.js');
const llm = await import('../../src/shield/llm.js');
const { shield } = await import('../../src/commands/shield.js');

const AGENT = 'agent-a';
const FORGED_TARGET = 'forged.example';

let tempHome: string;
let targetDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-verified-home-'));
  targetDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-verified-target-'));
  _mockHomeDir = tempHome;
  getShieldDir();
  vi.mocked(llm.suggestPolicy).mockClear();
  vi.mocked(llm.explainAnomaly).mockClear();
  vi.mocked(llm.triageIncident).mockClear();
});

afterEach(() => {
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(targetDir, { recursive: true, force: true });
});

function makePartial(overrides: Partial<ShieldEvent> = {}) {
  return {
    source: 'shield' as ShieldEvent['source'],
    category: 'network',
    severity: 'high' as ShieldEvent['severity'],
    agent: AGENT,
    sessionId: 's1',
    action: 'network.connect',
    target: 'api.example',
    outcome: 'allowed' as ShieldEvent['outcome'],
    detail: {},
    orgId: null,
    managed: false,
    agentId: null,
    ...overrides,
  };
}

/** Append a line whose hashes do not chain onto the genuine tail. */
function appendForgedEvent(overrides: Partial<ShieldEvent> = {}): ShieldEvent {
  const forged = {
    id: '00000000-0000-7000-8000-000000000000',
    timestamp: new Date().toISOString(),
    version: 1 as const,
    ...makePartial({ target: FORGED_TARGET, ...overrides }),
    prevHash: 'f0'.repeat(32),
    eventHash: '0f'.repeat(32),
  } as ShieldEvent;
  fs.appendFileSync(getEventsPath(), JSON.stringify(forged) + '\n');
  return forged;
}

async function run(subcommand: string, extra: Record<string, unknown> = {}): Promise<{ code: number; out: string }> {
  const chunks: string[] = [];
  const out = vi.spyOn(process.stdout, 'write').mockImplementation((s: string | Uint8Array) => {
    chunks.push(String(s));
    return true;
  });
  const err = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  try {
    const code = await shield({ subcommand, dir: targetDir, args: [], ...extra });
    return { code, out: chunks.join('') };
  } finally {
    out.mockRestore();
    err.mockRestore();
  }
}

describe('shield suggest', () => {
  it('builds the suggestion from verified events only and reports the break', async () => {
    writeEvent(makePartial());
    writeEvent(makePartial());
    appendForgedEvent();

    const { code, out } = await run('suggest', { format: 'json' });

    expect(code).toBe(0);
    const [, summary] = vi.mocked(llm.suggestPolicy).mock.calls[0];
    expect(summary.totalActions).toBe(2);
    expect(summary.topNetworkHosts.map(h => h.host)).not.toContain(FORGED_TARGET);
    const json = JSON.parse(out);
    expect(json.verification).toEqual({ chainBroken: true, brokenAt: 2, untrustedCount: 1 });
  });

  it('says the events left out are unverified and names the fresh-chain command', async () => {
    writeEvent(makePartial());
    appendForgedEvent();

    const { out } = await run('suggest');

    expect(out).toContain('Event chain breaks at event 2');
    expect(out).toContain('opena2a shield recover --archive-log');
  });

  it('reports an intact chain as intact', async () => {
    writeEvent(makePartial());

    const { out } = await run('suggest', { format: 'json' });

    expect(JSON.parse(out).verification).toEqual({ chainBroken: false, brokenAt: null, untrustedCount: 0 });
  });

  it('sends nothing to the LLM when every event is past the break', async () => {
    appendForgedEvent();

    const { code, out } = await run('suggest');

    expect(code).toBe(0);
    expect(llm.suggestPolicy).not.toHaveBeenCalled();
    expect(out).toContain('No verified events found.');
    expect(out).toContain('opena2a shield recover --archive-log');
  });
});

describe('shield explain', () => {
  it('lists an event past the break as unverified and never explains it', async () => {
    writeEvent(makePartial());
    const forged = appendForgedEvent();

    const { code, out } = await run('explain', { format: 'json' });

    expect(code).toBe(0);
    expect(llm.explainAnomaly).not.toHaveBeenCalled();
    const json = JSON.parse(out);
    expect(json).toHaveLength(1);
    expect(json[0].event.id).toBe(forged.id);
    expect(json[0].verified).toBe(false);
    expect(json[0].explanation).toBeNull();
  });

  it('explains verified events, keeps the window, and labels each event', async () => {
    const genuine = writeEvent(makePartial());
    appendForgedEvent();

    const { out } = await run('explain', { format: 'json', count: '5' });

    const json = JSON.parse(out);
    expect(json.map((r: { verified: boolean }) => r.verified)).toEqual([false, true]);
    expect(vi.mocked(llm.explainAnomaly).mock.calls.map(c => c[0].id)).toEqual([genuine.id]);
  });

  it('builds the normal-behaviour baseline from verified events only', async () => {
    writeEvent(makePartial());
    appendForgedEvent();

    await run('explain', { format: 'json', count: '5' });

    const [, context] = vi.mocked(llm.explainAnomaly).mock.calls[0];
    expect(context.normalActions.join('\n')).not.toContain(FORGED_TARGET);
  });

  it('marks the unverified event in text output', async () => {
    writeEvent(makePartial());
    appendForgedEvent();

    const { out } = await run('explain');

    expect(out).toContain('UNVERIFIED');
    expect(out).toContain('Event chain breaks at event 2');
  });
});

describe('shield triage', () => {
  it('triages verified events only and reports the break', async () => {
    const genuine = writeEvent(makePartial());
    appendForgedEvent();

    const { code, out } = await run('triage', { format: 'json' });

    expect(code).toBe(0);
    const [events, context] = vi.mocked(llm.triageIncident).mock.calls[0];
    expect(events.map(e => e.id)).toEqual([genuine.id]);
    expect(context.recentBaseline.join('\n')).not.toContain(FORGED_TARGET);
    expect(JSON.parse(out).verification).toEqual({ chainBroken: true, brokenAt: 1, untrustedCount: 1 });
  });

  it('sends nothing to the LLM when every matching event is past the break', async () => {
    writeEvent(makePartial({ severity: 'low' }));
    appendForgedEvent();

    const { out } = await run('triage');

    expect(llm.triageIncident).not.toHaveBeenCalled();
    expect(out).toContain('No verified high+ severity events found.');
    expect(out).toContain('Event chain breaks at event 2');
  });
});

describe('shield monitor', () => {
  function writeArpLog(ids: string[]): void {
    const arpDir = path.join(targetDir, '.opena2a', 'arp');
    fs.mkdirSync(arpDir, { recursive: true });
    const lines = ids.map(id => JSON.stringify({
      id,
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'spawn',
      data: { command: '/bin/sh' },
    }));
    fs.writeFileSync(path.join(arpDir, 'events.jsonl'), lines.join('\n') + '\n');
  }

  function forgedArpEvent(arpEventId: string): Partial<ShieldEvent> {
    return {
      source: 'arp',
      category: 'arp.process',
      severity: 'critical',
      outcome: 'blocked',
      detail: { arpEventId, arpCategory: 'threat' },
    };
  }

  it('counts only verified ARP events and reports the break', async () => {
    writeEvent(makePartial());
    appendForgedEvent(forgedArpEvent('arp-forged'));

    const { out } = await run('monitor', { format: 'json' });

    const json = JSON.parse(out);
    expect(json.stats.totalEvents).toBe(0);
    expect(json.stats.threats).toBe(0);
    expect(json.verification).toEqual({ chainBroken: true, brokenAt: 1, untrustedCount: 1 });
  });

  it('reports an import skipped only on an unverified record as unverified', async () => {
    writeEvent(makePartial());
    appendForgedEvent(forgedArpEvent('arp-1'));
    writeArpLog(['arp-1', 'arp-2']);

    const { out } = await run('monitor', { format: 'json' });

    const json = JSON.parse(out);
    expect(json.import.skipped).toBe(1);
    expect(json.import.skippedUnverified).toBe(1);
    expect(json.import.imported).toBe(1);
  });

  it('says how to import the events an unverified record held back', async () => {
    writeEvent(makePartial());
    appendForgedEvent(forgedArpEvent('arp-1'));
    writeArpLog(['arp-1']);

    const { out } = await run('monitor');

    expect(out).toContain('1 recorded only past a chain break');
    expect(out).toContain('opena2a shield recover --archive-log');
  });
});
