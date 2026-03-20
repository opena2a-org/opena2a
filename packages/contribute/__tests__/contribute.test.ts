import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { existsSync, writeFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { contribute } from '../src/index.js';
import { clearQueue, getQueuedEvents } from '../src/queue.js';

const CONFIG_DIR = join(homedir(), '.opena2a');
const CONFIG_PATH = join(CONFIG_DIR, 'config.json');
const QUEUE_PATH = join(CONFIG_DIR, 'contribute-queue.json');

describe('contribute.scanResult integration', () => {
  const originalFetch = globalThis.fetch;
  let originalConfig: string | null = null;
  let originalQueue: string | null = null;

  beforeEach(() => {
    // Back up existing files
    if (existsSync(CONFIG_PATH)) {
      originalConfig = readFileSync(CONFIG_PATH, 'utf-8');
    }
    if (existsSync(QUEUE_PATH)) {
      originalQueue = readFileSync(QUEUE_PATH, 'utf-8');
    }
    // Start with clean queue
    clearQueue();
    // Enable contributions for tests
    if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify({ contribute: { enabled: true } }), { mode: 0o600 });
    // Mock fetch to prevent real network calls
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
  });

  afterEach(() => {
    clearQueue();
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
    // Restore originals
    if (originalConfig !== null) {
      writeFileSync(CONFIG_PATH, originalConfig, { mode: 0o600 });
    }
    if (originalQueue !== null) {
      writeFileSync(QUEUE_PATH, originalQueue, { mode: 0o600 });
    }
    originalConfig = null;
    originalQueue = null;
  });

  it('queues a scan result event when enabled', async () => {
    await contribute.scanResult({
      tool: 'hackmyagent',
      toolVersion: '0.10.0',
      packageName: 'test-package',
      ecosystem: 'npm',
      totalChecks: 147,
      passed: 145,
      critical: 0,
      high: 1,
      medium: 1,
      low: 0,
      score: 95,
      verdict: 'pass',
      durationMs: 1200,
    });

    const events = getQueuedEvents();
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('scan_result');
    expect(events[0].tool).toBe('hackmyagent');
    expect(events[0].package?.name).toBe('test-package');
    expect(events[0].scanSummary?.critical).toBe(0);
    expect(events[0].scanSummary?.high).toBe(1);
  });

  it('does not queue when contributions are disabled', async () => {
    writeFileSync(CONFIG_PATH, JSON.stringify({ contribute: { enabled: false } }), { mode: 0o600 });

    await contribute.scanResult({
      tool: 'test',
      toolVersion: '1.0.0',
      packageName: 'disabled-test',
      totalChecks: 10,
      passed: 10,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      score: 100,
      verdict: 'pass',
      durationMs: 100,
    });

    expect(getQueuedEvents()).toHaveLength(0);
  });

  it('auto-flushes after 10 events', async () => {
    for (let i = 0; i < 10; i++) {
      await contribute.scanResult({
        tool: 'test',
        toolVersion: '1.0.0',
        packageName: `package-${i}`,
        totalChecks: 10,
        passed: 10,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        score: 100,
        verdict: 'pass',
        durationMs: 100,
      });
    }

    // After 10 events, flush should have been triggered
    expect(globalThis.fetch).toHaveBeenCalled();
    // Queue should be empty after successful flush
    expect(getQueuedEvents()).toHaveLength(0);
  });

  it('queues detection events when enabled', async () => {
    await contribute.detection({
      tool: 'opena2a-detect',
      toolVersion: '0.6.0',
      agentsFound: 3,
      mcpServersFound: 2,
      frameworkTypes: ['langchain', 'crewai'],
    });

    const events = getQueuedEvents();
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('detection');
    expect(events[0].detectionSummary?.agentsFound).toBe(3);
  });

  it('flush returns true when queue is empty', async () => {
    const result = await contribute.flush();
    expect(result).toBe(true);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('flush sends queued events and clears queue on success', async () => {
    await contribute.scanResult({
      tool: 'test',
      toolVersion: '1.0.0',
      packageName: 'flush-test',
      totalChecks: 5,
      passed: 5,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      score: 100,
      verdict: 'pass',
      durationMs: 50,
    });

    expect(getQueuedEvents()).toHaveLength(1);
    const result = await contribute.flush();
    expect(result).toBe(true);
    expect(getQueuedEvents()).toHaveLength(0);
  });

  it('flush keeps events in queue on submission failure', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 });

    await contribute.scanResult({
      tool: 'test',
      toolVersion: '1.0.0',
      packageName: 'fail-test',
      totalChecks: 5,
      passed: 5,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      score: 100,
      verdict: 'pass',
      durationMs: 50,
    });

    const result = await contribute.flush();
    expect(result).toBe(false);
    // Events should remain in queue for retry
    expect(getQueuedEvents()).toHaveLength(1);
  });
});
