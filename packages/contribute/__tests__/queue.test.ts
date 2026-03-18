import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { queueEvent, getQueuedEvents, clearQueue, shouldFlush, buildBatch } from '../src/queue.js';

describe('contribution queue', () => {
  beforeEach(() => {
    clearQueue();
  });

  afterEach(() => {
    clearQueue();
  });

  it('queues and retrieves events', () => {
    queueEvent({
      type: 'scan_result',
      tool: 'hackmyagent',
      toolVersion: '0.10.0',
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

    const events = getQueuedEvents();
    expect(events).toHaveLength(1);
    expect(events[0].tool).toBe('hackmyagent');
  });

  it('reports shouldFlush after threshold', () => {
    for (let i = 0; i < 9; i++) {
      queueEvent({
        type: 'scan_result',
        tool: 'test',
        toolVersion: '1.0',
        timestamp: new Date().toISOString(),
      });
    }
    expect(shouldFlush()).toBe(false);

    queueEvent({
      type: 'scan_result',
      tool: 'test',
      toolVersion: '1.0',
      timestamp: new Date().toISOString(),
    });
    expect(shouldFlush()).toBe(true);
  });

  it('builds batch with contributor token', () => {
    queueEvent({
      type: 'scan_result',
      tool: 'test',
      toolVersion: '1.0',
      timestamp: new Date().toISOString(),
    });
    const batch = buildBatch();
    expect(batch).not.toBeNull();
    expect(batch!.contributorToken).toMatch(/^[a-f0-9]{64}$/);
    expect(batch!.events).toHaveLength(1);
  });

  it('returns null batch when queue is empty', () => {
    expect(buildBatch()).toBeNull();
  });

  it('caps queue at max size', () => {
    for (let i = 0; i < 120; i++) {
      queueEvent({
        type: 'scan_result',
        tool: 'test',
        toolVersion: '1.0',
        timestamp: new Date().toISOString(),
      });
    }
    const events = getQueuedEvents();
    expect(events.length).toBeLessThanOrEqual(100);
  });
});
