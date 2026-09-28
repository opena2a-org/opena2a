import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AIMServerReporter } from './reporter';
import type { AuditEvent } from './types';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-reporter-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

function makeEvent(plugin: string, action: string): AuditEvent {
  return {
    timestamp: new Date().toISOString(),
    plugin,
    action,
    target: 'test-target',
    result: 'allowed',
  };
}

describe('AIMServerReporter', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('enqueues events', () => {
    const reporter = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
    });

    reporter.enqueue(makeEvent('test', 'scan'));
    reporter.enqueue(makeEvent('test', 'fix'));

    expect(reporter.getQueueLength()).toBe(2);
  });

  it('persists queue to disk', () => {
    const reporter = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
    });

    reporter.enqueue(makeEvent('test', 'persist'));

    const queuePath = path.join(dir, 'report-queue.jsonl');
    expect(fs.existsSync(queuePath)).toBe(true);

    const content = fs.readFileSync(queuePath, 'utf-8').trim();
    const parsed = JSON.parse(content);
    expect(parsed.plugin).toBe('test');
    expect(parsed.action).toBe('persist');
  });

  it('loads queue from disk on init', () => {
    // First reporter writes queue
    const reporter1 = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
    });
    reporter1.enqueue(makeEvent('test', 'queued'));

    // Second reporter should load it
    const reporter2 = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
    });
    expect(reporter2.getQueueLength()).toBe(1);
  });

  it('trims queue at max size, dropping the oldest events', () => {
    // Every enqueue rewrites the whole queue file, so 1010 events at the
    // default cap wrote about 75 MB and timed out at 5000 ms on a loaded CI
    // runner (unit 10042). A small cap keeps the cell off the disk; a large
    // batch size keeps the auto-flush from reaching for the network mid-loop.
    const reporter = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
      maxQueueSize: 10,
      maxBatchSize: 1000,
    });

    for (let i = 0; i < 12; i++) {
      reporter.enqueue(makeEvent('test', `action-${i}`));
    }

    expect(reporter.getQueueLength()).toBe(10);
    const persisted = fs
      .readFileSync(path.join(dir, 'report-queue.jsonl'), 'utf-8')
      .trim()
      .split('\n');
    expect(persisted).toHaveLength(10);
    expect((JSON.parse(persisted[0]) as AuditEvent).action).toBe('action-2');
    expect((JSON.parse(persisted[9]) as AuditEvent).action).toBe('action-11');
  });

  it('treats a queue cap below 1 as 1, so the queue is still bounded', () => {
    // slice(-0) returns the whole array, so a cap of 0 taken as given would
    // never trim.
    for (const maxQueueSize of [0, -5]) {
      const reporter = new AIMServerReporter({
        serverUrl: 'https://aim.example.com',
        agentId: 'aim_test123',
        dataDir: fs.mkdtempSync(path.join(dir, 'cap-')),
        maxQueueSize,
        maxBatchSize: 1000,
      });
      reporter.enqueue(makeEvent('test', 'a'));
      reporter.enqueue(makeEvent('test', 'b'));
      expect(reporter.getQueueLength()).toBe(1);
    }
  });

  it('keeps 1000 queued events by default', () => {
    // The default cap, proven with one write: a persisted queue of 1000
    // events plus one more enqueue trims back to 1000, oldest first.
    const seeded = Array.from({ length: 1000 }, (_, i) =>
      JSON.stringify(makeEvent('test', `seed-${i}`)),
    );
    fs.writeFileSync(path.join(dir, 'report-queue.jsonl'), seeded.join('\n') + '\n', 'utf-8');

    const reporter = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
      maxBatchSize: 5000,
    });
    expect(reporter.getQueueLength()).toBe(1000);

    reporter.enqueue(makeEvent('test', 'one-more'));

    expect(reporter.getQueueLength()).toBe(1000);
    const persisted = fs
      .readFileSync(path.join(dir, 'report-queue.jsonl'), 'utf-8')
      .trim()
      .split('\n');
    expect((JSON.parse(persisted[0]) as AuditEvent).action).toBe('seed-1');
    expect((JSON.parse(persisted[999]) as AuditEvent).action).toBe('one-more');
  });

  it('flush returns 0 sent when server unreachable', async () => {
    const reporter = new AIMServerReporter({
      serverUrl: 'https://localhost:99999',
      agentId: 'aim_test123',
      dataDir: dir,
    });

    reporter.enqueue(makeEvent('test', 'fail'));
    const result = await reporter.flush();

    expect(result.sent).toBe(0);
    expect(result.failed).toBeGreaterThan(0);
    expect(result.queued).toBeGreaterThan(0); // Still in queue for retry
  });

  it('flush with empty queue returns immediately', async () => {
    const reporter = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
    });

    const result = await reporter.flush();
    expect(result.sent).toBe(0);
    expect(result.failed).toBe(0);
    expect(result.queued).toBe(0);
  });
});
