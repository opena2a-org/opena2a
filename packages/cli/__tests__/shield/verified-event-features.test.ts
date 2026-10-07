/**
 * suggest, explain, triage, monitor and log read the event log through the
 * chain-verified reader.
 *
 * Each of them used to read the raw log, so a line appended without
 * recomputing the hash chain reached the LLM prompt, the policy suggestion,
 * the incident triage, the ARP import and the log listing as if it were a
 * recorded event.  Now an event at or after a chain break is never sent to
 * the LLM or counted.  suggest, triage and monitor report the log's
 * verification status: a `verification` object in JSON, also when there is
 * no result to print, and the break notice in text.  explain and log label
 * each event they list as verified or not, and print the notice in text.
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

  it('counts as already imported only the events a verified record names', async () => {
    writeEvent(makePartial(forgedArpEvent('arp-0')));
    appendForgedEvent(forgedArpEvent('arp-1'));
    writeArpLog(['arp-0', 'arp-1']);

    const { out } = await run('monitor');

    expect(out).toContain('1 already imported');
    expect(out).toContain('1 recorded only past a chain break');
  });

  it('prints how many ARP events the break holds back, and counts none of them', async () => {
    writeEvent(makePartial(forgedArpEvent('arp-0')));
    appendForgedEvent(forgedArpEvent('arp-1'));
    appendForgedEvent(forgedArpEvent('arp-2'));

    const { out: json } = await run('monitor', { format: 'json' });
    const { out } = await run('monitor');

    const data = JSON.parse(json);
    expect(data.stats.totalEvents).toBe(1);
    expect(data.stats.threats).toBe(1);
    expect(data.unverifiedStats.totalEvents).toBe(2);
    expect(data.unverifiedStats.threats).toBe(2);
    expect(out).toContain('Unverified, not counted');
    expect(out).toContain('2 ARP events, 2 threats past the chain break in this period');
    expect(out).toMatch(/Total events\s+1\n/);
  });

  it('names one held-back ARP event and detection in the singular', async () => {
    writeEvent(makePartial());
    appendForgedEvent(forgedArpEvent('arp-1'));

    const { out } = await run('monitor');

    expect(out).toContain('1 ARP event, 1 threat past the chain break in this period');
  });

  it('prints no unverified counts for an intact log', async () => {
    writeEvent(makePartial(forgedArpEvent('arp-0')));

    const { out: json } = await run('monitor', { format: 'json' });
    const { out } = await run('monitor');

    expect(JSON.parse(json).unverifiedStats.totalEvents).toBe(0);
    expect(out).not.toContain('Unverified, not counted');
  });
});

describe('shield log', () => {
  it('lists every event and marks each one past the break as unverified in json', async () => {
    const t0 = writeEvent(makePartial({ target: 't0.example' }));
    const t1 = writeEvent(makePartial({ target: 't1.example' }));
    const forged = appendForgedEvent();

    const { code, out } = await run('log', { format: 'json' });

    expect(code).toBe(0);
    const json = JSON.parse(out);
    expect(json.map((e: ShieldEvent) => e.id)).toEqual([forged.id, t1.id, t0.id]);
    expect(json.map((e: { verified: boolean }) => e.verified)).toEqual([false, true, true]);
    // The array keeps its shape: each entry is the event, plus its status.
    expect(json[1]).toEqual({ ...t1, verified: true });
  });

  it('reports a forged line that claims to be verified as unverified', async () => {
    writeEvent(makePartial());
    appendForgedEvent({ verified: true } as Partial<ShieldEvent>);

    const { out } = await run('log', { format: 'json' });

    expect(JSON.parse(out)[0].verified).toBe(false);
  });

  it('marks every event after an interior deletion as unverified', async () => {
    for (const target of ['t0', 't1', 't2', 't3']) writeEvent(makePartial({ target }));
    const lines = fs.readFileSync(getEventsPath(), 'utf-8').split('\n');
    lines.splice(1, 1);
    fs.writeFileSync(getEventsPath(), lines.join('\n'));

    const { out } = await run('log', { format: 'json' });

    const json = JSON.parse(out);
    expect(json.map((e: ShieldEvent) => e.target)).toEqual(['t3', 't2', 't0']);
    expect(json.map((e: { verified: boolean }) => e.verified)).toEqual([false, false, true]);
  });

  it('keeps the newest --count matching events across the break', async () => {
    writeEvent(makePartial({ target: 't0' }));
    writeEvent(makePartial({ target: 't1' }));
    appendForgedEvent({ target: 'f0' });
    appendForgedEvent({ target: 'f1' });

    const { out } = await run('log', { format: 'json', count: '3' });

    const json = JSON.parse(out);
    expect(json.map((e: ShieldEvent) => e.target)).toEqual(['f1', 'f0', 't1']);
    expect(json.map((e: { verified: boolean }) => e.verified)).toEqual([false, false, true]);
  });

  it('prints the break once and marks only the events past it in text', async () => {
    writeEvent(makePartial({ target: 't0.example' }));
    writeEvent(makePartial({ target: 't1.example' }));
    appendForgedEvent();

    const { code, out } = await run('log');

    expect(code).toBe(0);
    expect(out.split('Event chain breaks at event 3.')).toHaveLength(2);
    expect(out).toContain('opena2a shield recover --archive-log');
    const rows = out.split('\n').filter(line => line.includes('network.connect'));
    expect(rows).toHaveLength(3);
    expect(rows[0]).toContain(FORGED_TARGET);
    expect(rows[0]).toContain('UNVERIFIED');
    expect(rows[1]).not.toContain('UNVERIFIED');
    expect(rows[2]).not.toContain('UNVERIFIED');
  });

  it('prints no marker and no notice for an intact log', async () => {
    writeEvent(makePartial());
    writeEvent(makePartial());

    const { code, out: text } = await run('log');
    const { out: json } = await run('log', { format: 'json' });

    expect(code).toBe(0);
    expect(text).not.toContain('UNVERIFIED');
    expect(text).not.toContain('Event chain breaks');
    expect(JSON.parse(json).map((e: { verified: boolean }) => e.verified)).toEqual([true, true]);
  });
});

describe('shield suggest and triage with no result', () => {
  it('suggest --format json prints JSON with the status when every event is past the break', async () => {
    appendForgedEvent();

    const { code, out } = await run('suggest', { format: 'json' });

    expect(code).toBe(0);
    expect(JSON.parse(out)).toEqual({
      status: 'no-verified-events',
      verification: { chainBroken: true, brokenAt: 0, untrustedCount: 1 },
    });
  });

  it('suggest --format json prints JSON for an empty log', async () => {
    const { out } = await run('suggest', { format: 'json' });

    expect(JSON.parse(out)).toEqual({
      status: 'no-events',
      verification: { chainBroken: false, brokenAt: null, untrustedCount: 0 },
    });
  });

  it('triage --format json prints JSON with the status when no verified event matches', async () => {
    writeEvent(makePartial({ severity: 'low' }));
    appendForgedEvent();

    const { code, out } = await run('triage', { format: 'json' });

    expect(code).toBe(0);
    expect(JSON.parse(out)).toEqual({
      status: 'no-verified-events',
      verification: { chainBroken: true, brokenAt: 1, untrustedCount: 1 },
    });
  });

  it('triage --format json prints JSON for an empty log', async () => {
    const { out } = await run('triage', { format: 'json' });

    expect(JSON.parse(out).status).toBe('no-events');
  });

  it('explain --format json prints an empty array when no event matches', async () => {
    const { out } = await run('explain', { format: 'json' });

    expect(JSON.parse(out)).toEqual([]);
  });

  it('suggest prints the break notice when the LLM returns no result', async () => {
    writeEvent(makePartial());
    appendForgedEvent();
    vi.mocked(llm.suggestPolicy).mockResolvedValueOnce(null);

    const { out } = await run('suggest');

    expect(out).toContain('LLM analysis unavailable');
    expect(out).toContain('Event chain breaks at event 2');
  });

  it('suggest --format json reports the status when the LLM returns no result', async () => {
    writeEvent(makePartial());
    appendForgedEvent();
    vi.mocked(llm.suggestPolicy).mockResolvedValueOnce(null);

    const { out } = await run('suggest', { format: 'json' });

    expect(JSON.parse(out)).toEqual({
      status: 'llm-unavailable',
      verification: { chainBroken: true, brokenAt: 1, untrustedCount: 1 },
    });
  });

  it('triage prints the break notice when the LLM returns no result', async () => {
    writeEvent(makePartial());
    appendForgedEvent();
    vi.mocked(llm.triageIncident).mockResolvedValueOnce(null);

    const { out } = await run('triage');

    expect(out).toContain('LLM analysis unavailable');
    expect(out).toContain('Event chain breaks at event 2');
  });

  it('triage --format json reports the status when the LLM returns no result', async () => {
    writeEvent(makePartial());
    appendForgedEvent();
    vi.mocked(llm.triageIncident).mockResolvedValueOnce(null);

    const { out } = await run('triage', { format: 'json' });

    expect(JSON.parse(out)).toEqual({
      status: 'llm-unavailable',
      verification: { chainBroken: true, brokenAt: 1, untrustedCount: 1 },
    });
  });
});

describe('shield triage --severity is a threshold', () => {
  it('triages a critical event under the default high threshold', async () => {
    const critical = writeEvent(makePartial({ severity: 'critical' }));

    const { code } = await run('triage', { format: 'json' });

    expect(code).toBe(0);
    const [events] = vi.mocked(llm.triageIncident).mock.calls[0];
    expect(events.map(e => e.id)).toEqual([critical.id]);
  });

  it('triages the named severity and every one above it', async () => {
    for (const severity of ['info', 'low', 'medium', 'high', 'critical'] as const) {
      writeEvent(makePartial({ severity }));
    }

    await run('triage', { format: 'json', severity: 'medium' });

    const [events] = vi.mocked(llm.triageIncident).mock.calls[0];
    expect(events.map(e => e.severity)).toEqual(['critical', 'high', 'medium']);
  });

  it('matches no event for a severity outside the order', async () => {
    writeEvent(makePartial({ severity: 'critical' }));

    const { out } = await run('triage', { severity: 'urgent' });

    expect(llm.triageIncident).not.toHaveBeenCalled();
    expect(out).toContain('No urgent+ severity events found.');
  });

  it('prints the break notice with the triage it does', async () => {
    writeEvent(makePartial());
    appendForgedEvent();

    const { out } = await run('triage');

    expect(llm.triageIncident).toHaveBeenCalledTimes(1);
    expect(out).toContain('Incident Triage');
    expect(out).toContain('Event chain breaks at event 2');
    expect(out).toContain('left out of the triage');
  });
});

describe('shield explain baseline agent', () => {
  it('takes the agent from the newest verified event, not from the unverified tail', async () => {
    writeEvent(makePartial({ agent: 'agent-b' }));
    appendForgedEvent({ agent: 'forged-agent' });

    await run('explain', { format: 'json', count: '5' });

    const [, context] = vi.mocked(llm.explainAnomaly).mock.calls[0];
    expect(context.agentName).toBe('agent-b');
  });
});

describe('shield log and explain --count without a positive number', () => {
  for (const count of ['0', 'all']) {
    it(`log lists every matching event for --count ${count}`, async () => {
      for (let i = 0; i < 21; i++) writeEvent(makePartial({ target: `t${i}` }));
      appendForgedEvent();

      const { out } = await run('log', { format: 'json', count });

      const json = JSON.parse(out);
      expect(json).toHaveLength(22);
      expect(json[0].verified).toBe(false);
      expect(json[21].target).toBe('t0');
    });

    it(`explain lists every matching event for --count ${count}`, async () => {
      writeEvent(makePartial());
      writeEvent(makePartial());
      appendForgedEvent();

      const { out } = await run('explain', { format: 'json', count });

      expect(JSON.parse(out).map((r: { verified: boolean }) => r.verified)).toEqual([false, true, true]);
      expect(llm.explainAnomaly).toHaveBeenCalledTimes(2);
    });
  }
});

describe('chain-break notice wording', () => {
  it('names one event past the break in the singular', async () => {
    writeEvent(makePartial());
    appendForgedEvent();

    const { out } = await run('log');

    expect(out).toContain('The event from there on is unverified and marked UNVERIFIED where listed.');
  });

  it('counts several events past the break in the plural', async () => {
    writeEvent(makePartial());
    appendForgedEvent();
    appendForgedEvent();

    const { out } = await run('log');

    expect(out).toContain('The 2 events from there on are unverified and marked UNVERIFIED where listed.');
  });
});

describe('shield log and explain print event fields as inert text', () => {
  const CONTROL = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/;

  it('a control sequence in a field cannot hide the UNVERIFIED marker', async () => {
    writeEvent(makePartial());
    writeEvent(makePartial());
    appendForgedEvent({ outcome: 'allowed)\u001b[8m' as ShieldEvent['outcome'] });

    const { out } = await run('log');

    const row = out.split('\n').find(line => line.includes(FORGED_TARGET)) ?? '';
    expect(row).not.toMatch(CONTROL);
    expect(row.endsWith('(allowed)[8m) UNVERIFIED')).toBe(true);
  });

  it('a line break or a format character in a field cannot forge a row', async () => {
    writeEvent(makePartial({
      target: 'a\n[2026-01-01T00:00:00.000Z] [INFO] fake -> b (allowed)‮',
    }));

    const { out } = await run('log');

    const rows = out.split('\n').filter(line => line.startsWith('['));
    expect(rows).toHaveLength(1);
    expect(rows[0]).not.toMatch(CONTROL);
  });

  it('explain prints the fields the same way', async () => {
    writeEvent(makePartial({ action: 'x\u001b]0;title\u0007y' }));
    appendForgedEvent({ target: 'p\u001b[8mq' });

    const { out } = await run('explain', { count: '5' });

    for (const line of out.split('\n')) expect(line).not.toMatch(CONTROL);
    expect(out).toContain('p[8mq');
    expect(out).toContain('x]0;titley');
  });
});

describe('an event whose severity is not a string', () => {
  it('log lists it instead of stopping', async () => {
    writeEvent(makePartial());
    appendForgedEvent({ severity: 5 as unknown as ShieldEvent['severity'] });

    const { code, out } = await run('log');

    expect(code).toBe(0);
    expect(out).toMatch(/\[5\] network\.connect -> forged\.example \(allowed\) UNVERIFIED/);
    expect(out.split('\n').filter(line => line.includes('network.connect'))).toHaveLength(2);
  });

  it('explain lists it instead of stopping', async () => {
    writeEvent(makePartial());
    appendForgedEvent({ severity: { level: 'high' } as unknown as ShieldEvent['severity'] });

    const { code, out } = await run('explain', { count: '5' });

    expect(code).toBe(0);
    expect(out).toContain('[{"LEVEL":"HIGH"}] network.connect -> forged.example');
  });
});
