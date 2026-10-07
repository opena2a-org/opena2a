/**
 * The Shield event log is verified in bounded chunks, never as one string.
 *
 * The longest string the runtime can create is `MAX_STRING_LENGTH`
 * characters (536,870,888 on current Node). A log one byte longer used to
 * throw ERR_STRING_TOO_LONG inside `readFileSync(path, 'utf-8')`: the reader
 * swallowed it and returned no events at all, so `review` saw an empty,
 * intact chain, `selfcheck` failed with "Failed to read events file", and
 * `recover --archive-log` refused the log as intact. Shield's own writer
 * rotates at 10 MB, so only another writer, or a deliberate extension, gets
 * there -- and a sparse extension costs a few KB of disk.
 *
 * The verdict now follows the log's content at any size, and the archive
 * digest is computed over the file in chunks.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { execFileSync, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { constants as bufferConstants } from 'node:buffer';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';

import type { ShieldEvent } from '../../src/shield/types.js';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

const {
  writeEvent,
  getEventsPath,
  getShieldDir,
  readEvents,
  readVerifiedEvents,
  verifyEventChain,
  verifyEventLog,
  sha256File,
} = await import('../../src/shield/events.js');
const { runIntegrityChecks } = await import('../../src/shield/integrity.js');
const { runShieldPhase } = await import('../../src/commands/review.js');
const { shield } = await import('../../src/commands/shield.js');

const MAX_STRING_LENGTH = bufferConstants.MAX_STRING_LENGTH;
/** Generous per-test budget for reading half a gigabyte of sparse file. */
const BIG_TIMEOUT_MS = 60_000;

let tempHome: string;
let targetDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-any-size-home-'));
  targetDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-any-size-target-'));
  _mockHomeDir = tempHome;
  getShieldDir();
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(targetDir, { recursive: true, force: true });
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

/** Extend the log to `size` bytes with a sparse run of NUL bytes. */
function extendTo(size: number): void {
  fs.truncateSync(getEventsPath(), size);
  expect(fs.statSync(getEventsPath()).size).toBe(size);
}

function eventChainCheck() {
  const check = runIntegrityChecks({}).checks.find(c => c.name === 'event-chain');
  expect(check).toBeDefined();
  return check!;
}

function silenceIo(): void {
  vi.spyOn(process.stdout, 'write').mockReturnValue(true);
  vi.spyOn(process.stderr, 'write').mockReturnValue(true);
}

function archives(): string[] {
  return fs.readdirSync(getShieldDir()).filter(f => /^events-.+\.jsonl$/.test(f));
}

describe('a log longer than the longest string the runtime can hold', () => {
  it('is verified from its content: 3 trusted events and 1 unreadable tail', () => {
    writeEvent(makePartial({ action: 'genuine-1' }));
    writeEvent(makePartial({ action: 'genuine-2' }));
    writeEvent(makePartial({ action: 'genuine-3' }));
    extendTo(MAX_STRING_LENGTH + 1);

    const verified = readVerifiedEvents();
    expect(verified.chainBroken).toBe(false);
    expect(verified.brokenAt).toBeNull();
    expect(verified.untrustedCount).toBe(0);
    expect(verified.events.map(e => e.action)).toEqual(['genuine-3', 'genuine-2', 'genuine-1']);

    expect(readEvents({ count: 2 }).map(e => e.action)).toEqual(['genuine-3', 'genuine-2']);

    const check = eventChainCheck();
    expect(check.status).toBe('pass');
    expect(check.detail).toBe(
      'Event chain valid across 3 events. 1 unreadable line was skipped, as review skips them.',
    );

    const review = runShieldPhase(targetDir);
    expect(review.chainBroken).toBe(false);
    expect(review.untrustedEventsExcluded).toBe(0);
  }, BIG_TIMEOUT_MS);

  it('still reports a chain break, and recover archives it with a digest of every byte', async () => {
    writeEvent(makePartial({ action: 'genuine-1' }));
    writeEvent(makePartial({ action: 'genuine-2' }));
    appendForgedEvent('forged-1');
    const content = fs.readFileSync(getEventsPath());
    extendTo(MAX_STRING_LENGTH + 1);

    const verified = readVerifiedEvents();
    expect(verified.chainBroken).toBe(true);
    expect(verified.brokenAt).toBe(2);
    expect(verified.untrustedCount).toBe(1);
    expect(verified.firstUntrusted?.action).toBe('forged-1');

    const check = eventChainCheck();
    expect(check.status).toBe('warn');
    expect(check.detail).toMatch(/^Event chain breaks at event 3 of 3\. /);

    // The file is the genuine content followed by NUL bytes up to the size.
    const expected = createHash('sha256').update(content);
    const zeros = Buffer.alloc(1024 * 1024);
    let left = MAX_STRING_LENGTH + 1 - content.length;
    while (left > 0) {
      const n = Math.min(left, zeros.length);
      expected.update(n === zeros.length ? zeros : zeros.subarray(0, n));
      left -= n;
    }
    const expectedSha = expected.digest('hex');

    silenceIo();
    expect(await shield({ subcommand: 'recover', archiveLog: true })).toBe(0);
    expect(archives().length).toBe(1);

    const anchor = readEvents({ count: 1 })[0];
    expect(anchor.action).toBe('shield.log-archived');
    expect(anchor.detail.archivedSha256).toBe(expectedSha);
    expect(anchor.detail.brokenAt).toBe(2);
    expect(anchor.detail.untrustedCount).toBe(1);
  }, BIG_TIMEOUT_MS);
});

describe('a log just below that limit', () => {
  // MAX_STRING_LENGTH - 1 bytes is the largest log a whole-string read
  // decoded; a log of exactly MAX_STRING_LENGTH bytes already failed.
  it('gets the same verdict as the oversized one', () => {
    writeEvent(makePartial({ action: 'genuine-1' }));
    writeEvent(makePartial({ action: 'genuine-2' }));
    writeEvent(makePartial({ action: 'genuine-3' }));
    extendTo(MAX_STRING_LENGTH - 1);

    const verified = readVerifiedEvents();
    expect(verified.chainBroken).toBe(false);
    expect(verified.events.length).toBe(3);

    const check = eventChainCheck();
    expect(check.status).toBe('pass');
    expect(check.detail).toBe(
      'Event chain valid across 3 events. 1 unreadable line was skipped, as review skips them.',
    );
  }, BIG_TIMEOUT_MS);
});

describe('chunked reading', () => {
  /** Characters of 1, 2, 3 and 4 UTF-8 bytes, so every chunk edge splits one. */
  const MIXED = 'aé€\u{1F600}';

  function writeMixedLog(): ShieldEvent[] {
    return [
      writeEvent(makePartial({ action: 'mixed-1', detail: { text: MIXED.repeat(5) } })),
      writeEvent(makePartial({ action: 'mixed-2', detail: { text: `${MIXED} ${MIXED}` } })),
      writeEvent(makePartial({ action: 'mixed-3', detail: { text: MIXED.repeat(9) } })),
    ];
  }

  it('decodes a multi-byte character split across a chunk edge exactly once', () => {
    const written = writeMixedLog();

    // Every chunk size from 1 byte up moves the edges across every
    // character width in the log.
    for (const chunkBytes of [1, 2, 3, 5, 7, 64]) {
      const result = verifyEventLog(getEventsPath(), { chunkBytes });
      expect(result.chainBroken).toBe(false);
      expect(result.unreadableLines).toBe(0);
      expect(result.trustedCount).toBe(3);
      expect([...result.events].reverse()).toEqual(written);
    }
  });

  it('assembles an event longer than one default chunk', () => {
    const written = writeEvent(makePartial({
      action: 'long',
      detail: { text: MIXED.repeat(250_000) }, // 2.5 MB of mixed-width characters
    }));
    expect(fs.statSync(getEventsPath()).size).toBeGreaterThan(2 * 1024 * 1024);

    const verified = readVerifiedEvents();
    expect(verified.chainBroken).toBe(false);
    expect(verified.events).toEqual([written]);
  });

  it('matches verifyEventChain over the same lines when a damaged line sits mid-log', () => {
    writeMixedLog();
    // Damage the second line in place: same length, no longer JSON.
    const lines = fs.readFileSync(getEventsPath(), 'utf-8').split('\n');
    lines[1] = '#' + lines[1].slice(1);
    fs.writeFileSync(getEventsPath(), lines.join('\n'), 'utf-8');

    const parsed = lines
      .filter(l => l.trim().length > 0)
      .flatMap(l => { try { return [JSON.parse(l) as ShieldEvent]; } catch { return []; } });
    const reference = verifyEventChain(parsed);
    expect(reference).toEqual({ valid: false, brokenAt: 1 });

    for (const chunkBytes of [1, 4, 1024]) {
      const result = verifyEventLog(getEventsPath(), { chunkBytes });
      expect(result.chainBroken).toBe(true);
      expect(result.brokenAt).toBe(reference.brokenAt);
      expect(result.trustedCount).toBe(1);
      expect(result.untrustedCount).toBe(1);
      expect(result.unreadableLines).toBe(1);
      expect(result.firstUntrusted?.action).toBe('mixed-3');
    }
  });

  it('counts a line longer than the line limit as unreadable', () => {
    const first = writeEvent(makePartial({ action: 'first' }));
    const line = fs.readFileSync(getEventsPath(), 'utf-8').trim();

    // The genuine line is held at exactly its own length, and refused one
    // character below it.
    expect(verifyEventLog(getEventsPath(), { maxLineChars: line.length }).events).toEqual([first]);
    const refused = verifyEventLog(getEventsPath(), { maxLineChars: line.length - 1 });
    expect(refused.events).toEqual([]);
    expect(refused.unreadableLines).toBe(1);
    expect(refused.chainBroken).toBe(false);
  });

  it('keeps only the caller window and counts the rest', () => {
    for (let i = 1; i <= 6; i++) {
      writeEvent(makePartial({ action: `e${i}`, severity: i % 2 === 0 ? 'high' : 'info' }));
    }
    const result = verifyEventLog(getEventsPath(), { filters: { severity: 'high', count: 2 } });
    expect(result.events.map(e => e.action)).toEqual(['e6', 'e4']);
    expect(result.trustedCount).toBe(6);

    const counts = verifyEventLog(getEventsPath(), { countsOnly: true });
    expect(counts.events).toEqual([]);
    expect(counts.trustedCount).toBe(6);
    expect(counts.chainBroken).toBe(false);
  });

  it('keeps the newest `count` matches once the window has trimmed a batch', () => {
    // Four matches against a count of 2 reach the batch trim (at twice the
    // count), which must leave exactly `count` events behind.
    for (let i = 1; i <= 4; i++) writeEvent(makePartial({ action: `e${i}` }));

    const result = verifyEventLog(getEventsPath(), { filters: { count: 2 } });
    expect(result.events.map(e => e.action)).toEqual(['e4', 'e3']);
    expect(readEvents({ count: 2 }).map(e => e.action)).toEqual(['e4', 'e3']);
  });

  it('reads a log holding only unreadable lines as empty, and says the lines were skipped', () => {
    fs.writeFileSync(getEventsPath(), 'garbage\n', 'utf-8');

    const check = eventChainCheck();
    expect(check.status).toBe('pass');
    expect(check.detail).toBe(
      'Event chain valid across 0 events. 1 unreadable line was skipped, as review skips them.',
    );
  });

  it.skipIf(process.platform === 'win32')(
    'refuses a named pipe at the log path instead of blocking on it',
    async () => {
      execFileSync('mkfifo', [getEventsPath()]);
      // A pipe with no writer blocks a plain open until one appears. This
      // child opens the pipe read-write after RESCUE_MS and holds it, so a
      // reader that blocks is released, and caught by the elapsed time,
      // rather than hanging the run; every later open then returns at once.
      const RESCUE_MS = 5_000;
      const rescue = spawn(process.execPath, ['-e', `
        const fs = require('node:fs');
        setTimeout(() => {
          try { fs.openSync(process.argv[1], 'r+'); } catch {}
          setInterval(() => {}, 1000);
        }, ${RESCUE_MS});
      `, getEventsPath()], { stdio: 'ignore' });
      try {
        const started = Date.now();
        expect(() => verifyEventLog(getEventsPath())).toThrow(/Not a regular file/);
        expect(readVerifiedEvents().events).toEqual([]);
        expect(readEvents()).toEqual([]);
        const check = eventChainCheck();
        expect(Date.now() - started).toBeLessThan(RESCUE_MS);
        expect(check.status).toBe('fail');
        // The pipe gets the verdict a directory at the same path gets, the
        // log the reader already refused as unreadable.
        fs.unlinkSync(getEventsPath());
        fs.mkdirSync(getEventsPath());
        expect({ ...check, checkedAt: '' }).toEqual({ ...eventChainCheck(), checkedAt: '' });
      } finally {
        rescue.kill();
      }
    },
    15_000,
  );

  it('hashes a file in chunks to the digest of its whole content', () => {
    for (let i = 0; i < 5; i++) writeEvent(makePartial({ detail: { text: `${MIXED}${i}` } }));
    const whole = createHash('sha256').update(fs.readFileSync(getEventsPath())).digest('hex');
    for (const chunkBytes of [1, 7, 4096]) {
      expect(sha256File(getEventsPath(), chunkBytes)).toBe(whole);
    }
  });

  it('refuses a log that is not a regular file, as it refused one it could not read', () => {
    fs.mkdirSync(getEventsPath());

    expect(() => verifyEventLog(getEventsPath())).toThrow();
    expect(readVerifiedEvents()).toEqual({
      events: [], untrusted: [], chainBroken: false, brokenAt: null,
      untrustedCount: 0, firstUntrusted: null,
    });
    const check = eventChainCheck();
    expect(check.status).toBe('fail');
    expect(check.detail).toBe('Failed to read events file.');
  });
});
