/**
 * The queue file is shared by every tool on the machine, and tools point at
 * different Registries. Each queued event records its Registry; a flush sends
 * and removes only the events recorded for the Registry it submits to, and
 * events from an older version with no recorded Registry are dropped, not sent.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const { home } = await vi.hoisted(async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { tmpdir } = await import('node:os');
  return { home: fs.mkdtempSync(path.join(tmpdir(), 'contribute-per-registry-home-')) };
});

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => home };
});

const { contribute } = await import('../src/index.js');
const { queueEvent, clearQueue, getQueuedEvents, buildBatch } = await import('../src/queue.js');

import type { ContributionBatch, ContributionEvent } from '../src/types.js';

const QUEUE_PATH = join(home, '.opena2a', 'contribute-queue.json');
const REGISTRY_A = 'https://registry-a.example';
const REGISTRY_B = 'https://registry-b.example';
const originalFetch = globalThis.fetch;

function event(tool: string): ContributionEvent {
  return {
    type: 'detection',
    tool,
    toolVersion: '1.0.0',
    timestamp: new Date().toISOString(),
    detectionSummary: { agentsFound: 1, mcpServersFound: 0 },
  };
}

/** Each request's URL and the tools named in its batch. */
function sent(fetchMock: ReturnType<typeof vi.fn>): Array<{ url: string; tools: string[]; raw: string }> {
  return fetchMock.mock.calls.map(([url, init]) => {
    const body = JSON.parse((init as { body: string }).body) as ContributionBatch;
    return { url: String(url), tools: body.events.map((e) => e.tool), raw: (init as { body: string }).body };
  });
}

beforeEach(() => {
  mkdirSync(join(home, '.opena2a'), { recursive: true });
  clearQueue();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
  clearQueue();
});

describe('a queue shared by tools on two Registries', () => {
  it('each flush sends only its own Registry\'s events and leaves the other\'s queued', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    queueEvent(event('tool-a-1'), REGISTRY_A);
    queueEvent(event('tool-b-1'), REGISTRY_B);
    queueEvent(event('tool-a-2'), REGISTRY_A);
    queueEvent(event('tool-b-2'), REGISTRY_B);

    expect(await contribute.flush(REGISTRY_A)).toBe(true);
    expect(sent(fetchMock)).toEqual([
      expect.objectContaining({
        url: `${REGISTRY_A}/api/v1/contribute`,
        tools: ['tool-a-1', 'tool-a-2'],
      }),
    ]);
    expect(getQueuedEvents(REGISTRY_A)).toHaveLength(0);
    expect(getQueuedEvents(REGISTRY_B).map((e) => e.tool)).toEqual(['tool-b-1', 'tool-b-2']);

    fetchMock.mockClear();
    expect(await contribute.flush(REGISTRY_B)).toBe(true);
    expect(sent(fetchMock)).toEqual([
      expect.objectContaining({
        url: `${REGISTRY_B}/api/v1/contribute`,
        tools: ['tool-b-1', 'tool-b-2'],
      }),
    ]);
    expect(getQueuedEvents()).toHaveLength(0);
  });

  it('a refused flush leaves both Registries\' events queued', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 }) as unknown as typeof fetch;

    queueEvent(event('tool-a'), REGISTRY_A);
    queueEvent(event('tool-b'), REGISTRY_B);

    expect(await contribute.flush(REGISTRY_A)).toBe(false);
    expect(getQueuedEvents(REGISTRY_A)).toHaveLength(1);
    expect(getQueuedEvents(REGISTRY_B)).toHaveLength(1);
  });

  it('a flush with nothing queued for its Registry makes no request and leaves the other\'s', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    queueEvent(event('tool-b'), REGISTRY_B);

    expect(await contribute.flush(REGISTRY_A)).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(getQueuedEvents(REGISTRY_B)).toHaveLength(1);
  });

  it('a trailing slash names the same Registry', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    queueEvent(event('tool-a'), `${REGISTRY_A}/`);

    expect(await contribute.flush(REGISTRY_A)).toBe(true);
    expect(sent(fetchMock)[0].tools).toEqual(['tool-a']);
    expect(getQueuedEvents()).toHaveLength(0);
  });

  it('the recorded Registry does not leave the machine in the batch', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    queueEvent(event('tool-a'), REGISTRY_A);
    await contribute.flush(REGISTRY_A);

    expect(sent(fetchMock)[0].raw).not.toContain('registry-a.example');
  });

  it('scanResult and detection record the registryUrl they were given', async () => {
    writeFileSync(join(home, '.opena2a', 'config.json'), JSON.stringify({ contribute: { enabled: true } }));
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 }) as unknown as typeof fetch;

    await contribute.detection({
      tool: 'detect-b',
      toolVersion: '1.0.0',
      agentsFound: 0,
      mcpServersFound: 0,
      registryUrl: REGISTRY_B,
    });

    expect(getQueuedEvents(REGISTRY_B).map((e) => e.tool)).toEqual(['detect-b']);
    expect(getQueuedEvents(REGISTRY_A)).toHaveLength(0);
  });
});

describe('legacy events with no recorded Registry', () => {
  it('are dropped, not sent to whichever Registry flushes', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    writeFileSync(QUEUE_PATH, JSON.stringify({ events: [event('legacy-1'), event('legacy-2')] }));
    queueEvent(event('tool-a'), REGISTRY_A);

    expect(getQueuedEvents().map((e) => e.tool)).toEqual(['tool-a']);
    expect(buildBatch()).toBeNull();

    expect(await contribute.flush(REGISTRY_A)).toBe(true);
    expect(sent(fetchMock)[0].tools).toEqual(['tool-a']);
    expect(JSON.parse(readFileSync(QUEUE_PATH, 'utf-8')).events).toEqual([]);
  });

  it('a queue of only legacy events makes no request on flush', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    writeFileSync(QUEUE_PATH, JSON.stringify({ events: [event('legacy')] }));

    expect(await contribute.flush()).toBe(true);
    expect(await contribute.flush(REGISTRY_A)).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

process.on('exit', () => rmSync(home, { recursive: true, force: true }));
