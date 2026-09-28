/**
 * Issue #244 (ask 2 and 3): a torn trailing write must not restart the
 * event chain at genesis, and `shield selfcheck` must agree with
 * `opena2a review` on whether the chain is intact.
 *
 * Before the fix, writeEvent read an unparseable last line, fell back to
 * GENESIS_HASH, and appended onto the unterminated fragment: the new event
 * was glued to the fragment (lost at read time) and every later event
 * chained off genesis mid-file, which review reports as a critical break
 * and uses to exclude every genuine event after it.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => _mockHomeDir,
  };
});

const { writeEvent, readVerifiedEvents, GENESIS_HASH, getShieldDir, getEventsPath } =
  await import('../../src/shield/events.js');

const { runIntegrityChecks } = await import('../../src/shield/integrity.js');

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-torn-write-test-'));
  _mockHomeDir = tempDir;
  getShieldDir();
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

function makePartial(action: string) {
  return {
    source: 'shield' as const,
    category: 'test',
    severity: 'info' as const,
    agent: null,
    sessionId: null,
    action,
    target: 'test-target',
    outcome: 'allowed' as const,
    detail: {},
    orgId: null,
    managed: false,
    agentId: null,
  };
}

function eventChainCheck() {
  const state = runIntegrityChecks({ shell: 'zsh' });
  const check = state.checks.find((c) => c.name === 'event-chain');
  expect(check).toBeDefined();
  return check!;
}

/** A torn append: the head of a JSON line with no closing brace and no newline. */
const TORN_FRAGMENT = '{"id":"0192f0c0-torn","timestamp":"2026-09-27T00:00:00.000Z","ver';

describe('writeEvent after a torn trailing write', () => {
  it('chains to the last valid event, not to genesis', () => {
    writeEvent(makePartial('first'));
    const second = writeEvent(makePartial('second'));
    fs.appendFileSync(getEventsPath(), TORN_FRAGMENT);

    const next = writeEvent(makePartial('after-tear'));

    expect(next.prevHash).not.toBe(GENESIS_HASH);
    expect(next.prevHash).toBe(second.eventHash);
  });

  it('starts the new event on its own line so it is not lost with the fragment', () => {
    writeEvent(makePartial('first'));
    fs.appendFileSync(getEventsPath(), TORN_FRAGMENT);

    const next = writeEvent(makePartial('after-tear'));

    const lines = fs.readFileSync(getEventsPath(), 'utf-8').split('\n').filter((l) => l.length > 0);
    expect(lines).toHaveLength(3);
    expect(lines[1]).toBe(TORN_FRAGMENT);
    expect(JSON.parse(lines[2]).id).toBe(next.id);
  });

  it('leaves a chain that review verifies as intact, with every genuine event trusted', () => {
    writeEvent(makePartial('first'));
    writeEvent(makePartial('second'));
    fs.appendFileSync(getEventsPath(), TORN_FRAGMENT);
    writeEvent(makePartial('third'));
    writeEvent(makePartial('fourth'));

    const verified = readVerifiedEvents();
    expect(verified.chainBroken).toBe(false);
    expect(verified.untrustedCount).toBe(0);
    expect(verified.events.map((e) => e.action)).toEqual(['fourth', 'third', 'second', 'first']);
  });

  it('recovers past a newline-terminated corrupted line and non-object JSON lines', () => {
    const first = writeEvent(makePartial('first'));
    fs.appendFileSync(getEventsPath(), '{"id":"broken"\nnull\n[1,2]\n');

    const next = writeEvent(makePartial('after-junk'));

    expect(next.prevHash).toBe(first.eventHash);
    expect(readVerifiedEvents().chainBroken).toBe(false);
  });

  it('anchors at genesis when the torn write was the first line of the log', () => {
    fs.writeFileSync(getEventsPath(), TORN_FRAGMENT);

    const next = writeEvent(makePartial('first-real'));

    expect(next.prevHash).toBe(GENESIS_HASH);
    const verified = readVerifiedEvents();
    expect(verified.chainBroken).toBe(false);
    expect(verified.events).toHaveLength(1);
  });

  it('still reports a break when a line between two events is damaged', () => {
    writeEvent(makePartial('first'));
    writeEvent(makePartial('second'));
    writeEvent(makePartial('third'));

    const lines = fs.readFileSync(getEventsPath(), 'utf-8').split('\n');
    lines[1] = '{"id":"damaged"';
    fs.writeFileSync(getEventsPath(), lines.join('\n'));

    const verified = readVerifiedEvents();
    expect(verified.chainBroken).toBe(true);
    expect(verified.brokenAt).toBe(1);
  });
});

describe('shield selfcheck event-chain agrees with review', () => {
  it('passes after a recovered torn write and says a line was skipped', () => {
    writeEvent(makePartial('first'));
    fs.appendFileSync(getEventsPath(), TORN_FRAGMENT);
    writeEvent(makePartial('second'));

    const check = eventChainCheck();
    expect(check.status).toBe('pass');
    expect(check.detail).toContain('valid across 2 events');
    expect(check.detail).toContain('1 unreadable line was skipped');
  });

  it('warns on a content edit that keeps the links intact, as review does', () => {
    writeEvent(makePartial('first'));
    writeEvent(makePartial('second'));

    // Rewrite the first event's action without recomputing its hash: every
    // prevHash link still matches, only the content hash does not.
    const content = fs.readFileSync(getEventsPath(), 'utf-8');
    fs.writeFileSync(getEventsPath(), content.replace('"action":"first"', '"action":"edited"'));

    expect(readVerifiedEvents().chainBroken).toBe(true);
    const check = eventChainCheck();
    expect(check.status).toBe('warn');
    expect(check.detail).toContain('breaks at event 1 of 2');
  });

  it('describes a break the way review treats it, with a fix command, and no reassurance', () => {
    writeEvent(makePartial('first'));
    writeEvent(makePartial('second'));
    fs.appendFileSync(
      getEventsPath(),
      JSON.stringify({ ...makePartial('forged'), prevHash: 'deadbeef', eventHash: 'deadbeef' }) + '\n',
    );

    const check = eventChainCheck();
    expect(check.status).toBe('warn');
    expect(check.detail).toContain('breaks at event 3 of 3');
    expect(check.detail).toContain('SHIELD-INT-002');
    expect(check.detail).toContain('excludes the 1 event from there on');
    expect(check.detail).toContain('opena2a shield recover --archive-log');
    expect(check.detail).not.toContain('common after updates');
    expect(check.detail).not.toContain('configuration is intact');
  });
});
