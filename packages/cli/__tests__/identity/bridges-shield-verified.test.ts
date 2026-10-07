/**
 * `identity attach` and `identity sync` import the Shield event log into the
 * AIM audit log through the chain-verified read.
 *
 * importShieldEvents parsed the log line by line, so a line appended without
 * recomputing the hash chain was logged into the audit log as a Shield event.
 * Now an event at or after the first chain break is counted as unverified
 * and never imported.
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
const { importShieldEvents, importAllToolEvents } = await import('../../src/identity/bridges.js');

interface Logged {
  action: string;
  target: string;
  result: 'allowed' | 'denied' | 'error';
  plugin: string;
  metadata?: Record<string, unknown>;
}

/** An AIM stand-in whose audit log is the list of events logged into it. */
function fakeAim() {
  const logged: Logged[] = [];
  return {
    logged,
    logEvent(event: Logged) {
      logged.push(event);
    },
    readAuditLog() {
      return logged.map(e => ({ ...e, timestamp: new Date().toISOString() }));
    },
  };
}

let tempHome: string;
let targetDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'identity-bridge-home-'));
  targetDir = fs.mkdtempSync(path.join(tmpdir(), 'identity-bridge-target-'));
  _mockHomeDir = tempHome;
  getShieldDir();
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
    agent: 'agent-a',
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
function appendForgedEvent(id: string): void {
  const forged = {
    id,
    timestamp: new Date().toISOString(),
    version: 1 as const,
    ...makePartial({ target: 'forged.example' }),
    prevHash: 'f0'.repeat(32),
    eventHash: '0f'.repeat(32),
  };
  fs.appendFileSync(getEventsPath(), JSON.stringify(forged) + '\n');
}

function importedIds(aim: ReturnType<typeof fakeAim>): unknown[] {
  return aim.logged.map(e => e.metadata?.sourceEventId);
}

describe('importShieldEvents', () => {
  it('imports the verified events in log order and leaves out every event past the break', () => {
    const first = writeEvent(makePartial({ target: 't0' }));
    const second = writeEvent(makePartial({ target: 't1' }));
    appendForgedEvent('forged-1');
    appendForgedEvent('forged-2');
    const aim = fakeAim();

    const result = importShieldEvents(aim);

    expect(result).toEqual({ imported: 2, skipped: 0, errors: 0, unverified: 2 });
    expect(importedIds(aim)).toEqual([first.id, second.id]);
    expect(aim.logged.map(e => e.target)).not.toContain('forged.example');
  });

  it('leaves out every event after an interior deletion', () => {
    const first = writeEvent(makePartial({ target: 't0' }));
    for (const target of ['t1', 't2', 't3']) writeEvent(makePartial({ target }));
    const lines = fs.readFileSync(getEventsPath(), 'utf-8').split('\n');
    lines.splice(1, 1);
    fs.writeFileSync(getEventsPath(), lines.join('\n'));
    const aim = fakeAim();

    const result = importShieldEvents(aim);

    expect(importedIds(aim)).toEqual([first.id]);
    expect(result.unverified).toBe(2);
  });

  it('counts an event it imported before as skipped, and the unverified tail again as unverified', () => {
    writeEvent(makePartial());
    appendForgedEvent('forged-1');
    const aim = fakeAim();
    importShieldEvents(aim);

    const again = importShieldEvents(aim);

    expect(again).toEqual({ imported: 0, skipped: 1, errors: 0, unverified: 1 });
    expect(aim.logged).toHaveLength(1);
  });

  it('imports every event of an intact log', () => {
    writeEvent(makePartial());
    writeEvent(makePartial());
    const aim = fakeAim();

    expect(importShieldEvents(aim)).toEqual({ imported: 2, skipped: 0, errors: 0, unverified: 0 });
  });

  it('counts an unparseable line as an error', () => {
    writeEvent(makePartial());
    fs.appendFileSync(getEventsPath(), '{not json\n');
    const aim = fakeAim();

    const result = importShieldEvents(aim);

    expect(result.imported).toBe(1);
    expect(result.errors).toBe(1);
  });
});

describe('importAllToolEvents', () => {
  it('carries the unverified Shield count into the total', () => {
    writeEvent(makePartial());
    appendForgedEvent('forged-1');
    const aim = fakeAim();

    const results = importAllToolEvents(aim, targetDir, { shield: true });

    expect(results.shield.unverified).toBe(1);
    expect(results.total).toEqual({ imported: 1, skipped: 0, errors: 0, unverified: 1 });
  });
});
