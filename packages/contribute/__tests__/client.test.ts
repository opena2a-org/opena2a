import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { submitBatch } from '../src/client.js';
import type { ContributionBatch } from '../src/types.js';

describe('submitBatch', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  function makeBatch(eventCount = 1): ContributionBatch {
    return {
      contributorToken: 'a'.repeat(64),
      events: Array.from({ length: eventCount }, (_, i) => ({
        type: 'scan_result' as const,
        tool: 'test-tool',
        toolVersion: '1.0.0',
        timestamp: new Date().toISOString(),
        scanSummary: {
          totalChecks: 10,
          passed: 9,
          critical: 0,
          high: 1,
          medium: 0,
          low: 0,
          score: 90,
          verdict: 'pass',
          durationMs: 500,
        },
      })),
      submittedAt: new Date().toISOString(),
    };
  }

  it('returns true on successful submission (200)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
    });

    const result = await submitBatch(makeBatch());
    expect(result).toBe(true);
    expect(globalThis.fetch).toHaveBeenCalledOnce();
  });

  it('sends POST to the correct URL', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

    await submitBatch(makeBatch(), 'https://custom.registry.org');
    const callArgs = (globalThis.fetch as any).mock.calls[0];
    expect(callArgs[0]).toBe('https://custom.registry.org/api/v1/contribute');
    expect(callArgs[1].method).toBe('POST');
  });

  it('uses default registry URL when none provided', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

    await submitBatch(makeBatch());
    const callArgs = (globalThis.fetch as any).mock.calls[0];
    expect(callArgs[0]).toBe('https://api.oa2a.org/api/v1/contribute');
  });

  it('returns false on server error (500)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
    });

    const result = await submitBatch(makeBatch());
    expect(result).toBe(false);
  });

  it('returns false on network error (offline)', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('fetch failed'));

    const result = await submitBatch(makeBatch());
    expect(result).toBe(false);
  });

  it('returns false on timeout (abort)', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new DOMException('aborted', 'AbortError'));

    const result = await submitBatch(makeBatch());
    expect(result).toBe(false);
  });

  it('strips trailing slashes from registry URL', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

    await submitBatch(makeBatch(), 'https://api.oa2a.org///');
    const callArgs = (globalThis.fetch as any).mock.calls[0];
    expect(callArgs[0]).toBe('https://api.oa2a.org/api/v1/contribute');
  });

  it('sends JSON content type header', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

    await submitBatch(makeBatch());
    const callArgs = (globalThis.fetch as any).mock.calls[0];
    expect(callArgs[1].headers['Content-Type']).toBe('application/json');
  });

  it('sends the batch as JSON body', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

    const batch = makeBatch(3);
    await submitBatch(batch);
    const callArgs = (globalThis.fetch as any).mock.calls[0];
    const body = JSON.parse(callArgs[1].body);
    expect(body.events).toHaveLength(3);
    expect(body.contributorToken).toBe('a'.repeat(64));
  });
});
