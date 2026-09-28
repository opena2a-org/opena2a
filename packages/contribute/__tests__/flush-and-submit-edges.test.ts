/**
 * Issue #299 — three library-UX findings from the 0.2.0 fresh-consumer test:
 *
 * 1. `flush(url, verbose: true)` against an unreachable Registry returned
 *    `false` with nothing on stdout or stderr.
 * 2. `submitBatch(null)` made a POST and resolved `true`.
 * 3. `flush()`'s return value was undocumented (now in the JSDoc and README).
 *
 * Plus the abort timer, which was only cleared on the success path: a failed
 * request left it pending and held the process open for up to 10s.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const { home } = await vi.hoisted(async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { tmpdir } = await import('node:os');
  return { home: fs.mkdtempSync(path.join(tmpdir(), 'contribute-edges-home-')) };
});

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => home };
});

const { submitBatch } = await import('../src/client.js');
const { contribute } = await import('../src/index.js');
const { queueEvent, clearQueue, getQueuedEvents } = await import('../src/queue.js');

import type { ContributionBatch, ContributionEvent } from '../src/types.js';

const originalFetch = globalThis.fetch;
let stderr = '';

function event(): ContributionEvent {
  return {
    type: 'detection',
    tool: 'test-tool',
    toolVersion: '1.0.0',
    timestamp: new Date().toISOString(),
    detectionSummary: { agentsFound: 1, mcpServersFound: 0 },
  };
}

function batch(events: ContributionEvent[] = [event()]): ContributionBatch {
  return { contributorToken: 'a'.repeat(64), events, submittedAt: new Date().toISOString() };
}

beforeEach(() => {
  stderr = '';
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    stderr += String(chunk);
    return true;
  });
  mkdirSync(join(home, '.opena2a'), { recursive: true });
  writeFileSync(join(home, '.opena2a', 'config.json'), JSON.stringify({ contribute: { enabled: true } }));
  clearQueue();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.useRealTimers();
  vi.restoreAllMocks();
  clearQueue();
});

describe('submitBatch with nothing to submit (#299 item 2)', () => {
  it('null makes no request and resolves false', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

    expect(await submitBatch(null)).toBe(false);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('an empty events array makes no request and resolves false', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

    expect(await submitBatch(batch([]))).toBe(false);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('says so under verbose', async () => {
    globalThis.fetch = vi.fn();

    await submitBatch(null, undefined, true);
    expect(stderr).toContain('nothing to submit');
  });
});

describe('unreachable Registry (#299 item 1)', () => {
  it('flush(url, true) prints the cause to stderr and keeps the events queued', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'));
    queueEvent(event());

    const ok = await contribute.flush('http://127.0.0.1:9', true);
    expect(ok).toBe(false);
    expect(stderr).toContain('could not reach the Registry at http://127.0.0.1:9/api/v1/contribute');
    expect(stderr).toContain('fetch failed');
    expect(getQueuedEvents()).toHaveLength(1);
  });

  it('stays silent without verbose', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'));

    expect(await submitBatch(batch())).toBe(false);
    expect(stderr).toBe('');
  });

  it('names the timeout when the request is aborted', async () => {
    vi.useFakeTimers();
    globalThis.fetch = vi.fn((_url: string, init: { signal: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(new Error('This operation was aborted')));
      })) as unknown as typeof fetch;

    const pending = submitBatch(batch(), undefined, true);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(await pending).toBe(false);
    expect(stderr).toContain('no response within 10s');
  });

  it('clears the abort timer when the request fails', async () => {
    vi.useFakeTimers();
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'));

    await submitBatch(batch());
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('flush() return (#299 item 3, documented)', () => {
  it('resolves true with no request when the queue is empty', async () => {
    globalThis.fetch = vi.fn();

    expect(await contribute.flush()).toBe(true);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('resolves true and clears the queue when the batch is accepted', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    queueEvent(event());

    expect(await contribute.flush()).toBe(true);
    expect(getQueuedEvents()).toHaveLength(0);
  });
});

process.on('exit', () => rmSync(home, { recursive: true, force: true }));
