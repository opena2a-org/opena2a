/**
 * `shield recover --archive-log` — the path to green for SHIELD-INT-002 (#231).
 *
 * The finding's remediation used to be `opena2a shield selfcheck && opena2a
 * shield recover --forensic`. Followed verbatim on a broken log, selfcheck
 * reported the config intact, recover reported "System is not in lockdown"
 * (a broken chain does not trigger lockdown), and `review` kept raising the
 * critical. The only exit was deleting `events.jsonl` by hand — in a
 * tamper-evidence system.
 *
 * The replacement archives the broken log instead of deleting it and anchors
 * its sha256 in the first event of the fresh chain, so the evidence survives
 * and the break cannot be laundered by rotating it away.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';

import type { ShieldEvent } from '../../src/shield/types.js';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

// The chain check recover runs, observed but not changed: the wrapper calls
// the real verifyEventLog and records what each call returned.
vi.mock('../../src/shield/events.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/shield/events.js')>();
  return { ...actual, verifyEventLog: vi.fn(actual.verifyEventLog) };
});

const { writeEvent, getEventsPath, getShieldDir, verifyEventChain, verifyEventLog } =
  await import('../../src/shield/events.js');
const { runShieldPhase } = await import('../../src/commands/review.js');
const { shield } = await import('../../src/commands/shield.js');

let tempHome: string;
let targetDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-archive-home-'));
  targetDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-archive-target-'));
  _mockHomeDir = tempHome;
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(targetDir, { recursive: true, force: true });
});

function silenceIo(): { restore: () => void } {
  const out = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
  const err = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  return { restore: () => { out.mockRestore(); err.mockRestore(); } };
}

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

/** Append a line whose hashes do not chain onto the genuine tail. */
function appendForgedEvent(action: string): void {
  const forged = {
    id: '00000000-0000-7000-8000-000000000000',
    timestamp: new Date().toISOString(),
    version: 1 as const,
    ...makePartial({ action }),
    prevHash: 'f0'.repeat(32),
    eventHash: '0f'.repeat(32),
  } as ShieldEvent;
  fs.appendFileSync(getEventsPath(), JSON.stringify(forged) + '\n', 'utf-8');
}

function archives(): string[] {
  return fs.readdirSync(getShieldDir())
    .filter(f => /^events-.+\.jsonl$/.test(f))
    .sort();
}

function readChain(): ShieldEvent[] {
  return fs.readFileSync(getEventsPath(), 'utf-8')
    .split('\n')
    .filter(l => l.trim().length > 0)
    .map(l => JSON.parse(l) as ShieldEvent);
}

function findingIds(): string[] {
  return runShieldPhase(targetDir).classifiedFindings.map(f => f.finding.id);
}

async function runArchive(): Promise<number> {
  const io = silenceIo();
  try {
    return await shield({ subcommand: 'recover', archiveLog: true });
  } finally {
    io.restore();
  }
}

describe('shield recover --archive-log', () => {
  it('archives a broken log, anchors its digest, and clears SHIELD-INT-002', async () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine-1' }));
    writeEvent(makePartial({ action: 'genuine-2' }));
    appendForgedEvent('forged-1');
    appendForgedEvent('forged-2');

    // The dead end this command exists to open.
    expect(findingIds()).toContain('SHIELD-INT-002');

    const before = fs.readFileSync(getEventsPath());
    const beforeSha = createHash('sha256').update(before).digest('hex');

    expect(await runArchive()).toBe(0);

    // Archived, not deleted — and exactly once.
    const archived = archives();
    expect(archived.length).toBe(1);
    const archivedBytes = fs.readFileSync(path.join(getShieldDir(), archived[0]));
    expect(archivedBytes.equals(before)).toBe(true);

    // The fresh chain opens with a verifiable pointer back to the evidence.
    const fresh = readChain();
    expect(fresh.length).toBe(1);
    expect(fresh[0].action).toBe('shield.log-archived');
    expect(fresh[0].detail.archivedSha256).toBe(beforeSha);
    expect(fresh[0].detail.archivedPath).toBe(path.join(getShieldDir(), archived[0]));
    expect(fresh[0].detail.brokenAt).toBe(2);
    expect(fresh[0].detail.untrustedCount).toBe(2);
    expect(verifyEventChain(fresh)).toEqual({ valid: true, brokenAt: null });

    // ...and review is clean again. The anchor event must not re-raise the
    // finding it just cleared.
    expect(findingIds()).not.toContain('SHIELD-INT-002');
  });

  it('refuses on an intact chain, leaving the log untouched', async () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine-1' }));
    writeEvent(makePartial({ action: 'genuine-2' }));
    const before = fs.readFileSync(getEventsPath());

    // Archiving an intact log discards trustworthy history for nothing, and
    // would be a supported way to drop events on demand.
    expect(await runArchive()).toBe(1);

    expect(archives()).toEqual([]);
    expect(fs.readFileSync(getEventsPath()).equals(before)).toBe(true);
  });

  it('refuses when there is no event log at all', async () => {
    getShieldDir();
    expect(fs.existsSync(getEventsPath())).toBe(false);

    expect(await runArchive()).toBe(1);

    expect(archives()).toEqual([]);
    expect(fs.existsSync(getEventsPath())).toBe(false);
  });

  it('runs outside lockdown, which is the only state a chain break produces', async () => {
    const integrity = await import('../../src/shield/integrity.js');
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine-1' }));
    appendForgedEvent('forged-1');

    // A broken chain never enters lockdown, so a branch placed behind the
    // `if (!isLockdown())` early return would be unreachable here.
    expect(integrity.isLockdown()).toBe(false);
    expect(await runArchive()).toBe(0);
    expect(archives().length).toBe(1);
  });

  it('reports the archive path and digest in json mode', async () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine-1' }));
    appendForgedEvent('forged-1');
    const beforeSha = createHash('sha256').update(fs.readFileSync(getEventsPath())).digest('hex');

    const chunks: string[] = [];
    const out = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      chunks.push(String(chunk));
      return true;
    });
    const code = await shield({ subcommand: 'recover', archiveLog: true, format: 'json' });
    out.mockRestore();

    expect(code).toBe(0);
    const payload = JSON.parse(chunks.join(''));
    expect(payload.status).toBe('archived');
    expect(payload.archivedSha256).toBe(beforeSha);
    expect(payload.archivedPath).toBe(path.join(getShieldDir(), archives()[0]));
    expect(payload.untrustedCount).toBe(1);
  });

  it('checks the chain without holding any event of the log', async () => {
    getShieldDir();
    writeEvent(makePartial({ action: 'genuine-1' }));
    writeEvent(makePartial({ action: 'genuine-2' }));
    for (let i = 1; i <= 40; i++) appendForgedEvent(`forged-${i}`);
    const check = vi.mocked(verifyEventLog);
    check.mockClear();

    expect(await runArchive()).toBe(0);

    // One pass over the log that keeps no event: every event is counted,
    // none is held, trusted or not.
    expect(check).toHaveBeenCalledTimes(1);
    expect(check).toHaveBeenCalledWith(path.join(getShieldDir(), 'events.jsonl'), { countsOnly: true });
    const result = check.mock.results[0];
    expect(result.type).toBe('return');
    if (result.type !== 'return') return;
    expect(result.value.events).toEqual([]);
    expect(result.value.untrusted).toEqual([]);
    expect(result.value.trustedCount).toBe(2);
    expect(result.value.untrustedCount).toBe(40);

    // The anchor still records the break from those counts.
    const fresh = readChain();
    expect(fresh.length).toBe(1);
    expect(fresh[0].detail.brokenAt).toBe(2);
    expect(fresh[0].detail.untrustedCount).toBe(40);
  });

  it('refuses a log it cannot read as unreadable, never as intact', async () => {
    getShieldDir();
    // A directory where the log belongs: it exists, and cannot be read as a log.
    fs.mkdirSync(getEventsPath());

    const chunks: string[] = [];
    const out = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      chunks.push(String(chunk));
      return true;
    });
    const code = await shield({ subcommand: 'recover', archiveLog: true, format: 'json' });
    out.mockRestore();

    expect(code).toBe(1);
    const payload = JSON.parse(chunks.join(''));
    expect(payload.status).toBe('unreadable');
    expect(payload.eventsPath).toBe(getEventsPath());
    expect(payload.error).toBe(`Not a regular file: ${getEventsPath()}`);

    // Nothing archived, nothing written: the path is left as it was found.
    expect(archives()).toEqual([]);
    expect(fs.statSync(getEventsPath()).isDirectory()).toBe(true);
  });

  it('names the read failure in text mode, with the command that inspects it', async () => {
    getShieldDir();
    fs.mkdirSync(getEventsPath());

    const errors: string[] = [];
    const err = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      errors.push(String(chunk));
      return true;
    });
    const out = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const code = await shield({ subcommand: 'recover', archiveLog: true });
    err.mockRestore();
    out.mockRestore();

    expect(code).toBe(1);
    const text = errors.join('');
    expect(text).toContain('Event log could not be read, so its hash chain was not checked. Nothing archived.');
    expect(text).toContain(`Reason:   Not a regular file: ${getEventsPath()}`);
    expect(text).toContain('Inspect:  opena2a shield selfcheck');
    expect(text).not.toContain('intact');
  });
});
