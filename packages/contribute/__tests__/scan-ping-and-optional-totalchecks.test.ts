/**
 * 0.2.0 widening: `scan_ping` joins the event union, and
 * `scanSummary.totalChecks` is optional — a tool reports it from a measured
 * coverage record or omits it; a derived stand-in number is worse than no
 * number.
 *
 * The widening is a type change, so its red-proof is `tsc --noEmit` on a
 * probe using both new shapes: it fails on 0.1.x and passes here (recorded
 * in the PR; esbuild-transpiled test runs cannot express a compile error).
 * These cells pin the RUNTIME contract: both shapes queue, survive
 * buildBatch, and the omitted field stays omitted — nothing fills it in.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { queueEvent, getQueuedEvents, clearQueue, buildBatch } from '../src/queue.js';
import type { ContributionEvent } from '../src/types.js';

describe('scan_ping and optional totalChecks (0.2.0)', () => {
  beforeEach(() => {
    clearQueue();
  });

  afterEach(() => {
    clearQueue();
  });

  it('a scan_ping event queues and rides the batch unchanged', () => {
    const ping: ContributionEvent = {
      type: 'scan_ping',
      tool: 'hackmyagent',
      toolVersion: '0.33.0',
      timestamp: new Date().toISOString(),
    };
    queueEvent(ping);

    const events = getQueuedEvents();
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('scan_ping');

    const batch = buildBatch();
    expect(batch?.events[0].type).toBe('scan_ping');
  });

  it('a scanSummary without totalChecks queues, and nothing fills the field in', () => {
    queueEvent({
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.33.0',
      timestamp: new Date().toISOString(),
      scanSummary: {
        passed: 12,
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        score: 87,
        verdict: 'pass',
        durationMs: 900,
      },
    });

    const [event] = getQueuedEvents();
    expect(event.scanSummary).toBeDefined();
    expect('totalChecks' in (event.scanSummary as object)).toBe(false);
    expect(event.scanSummary?.passed).toBe(12);

    const batch = buildBatch();
    expect('totalChecks' in (batch!.events[0].scanSummary as object)).toBe(false);
  });

  it('a scanSummary carrying totalChecks keeps it (the 0.1.x shape is a subset)', () => {
    queueEvent({
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.33.0',
      timestamp: new Date().toISOString(),
      scanSummary: {
        totalChecks: 147,
        passed: 145,
        critical: 0,
        high: 1,
        medium: 1,
        low: 0,
        score: 95,
        verdict: 'pass',
        durationMs: 1200,
      },
    });

    expect(getQueuedEvents()[0].scanSummary?.totalChecks).toBe(147);
  });
});
