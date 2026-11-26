import { it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AIMServerReporter } from './reporter';
import type { AuditEvent } from './types';

/** Run `fn` with the process umask set to `mask`, restoring the previous umask afterwards. */
function withUmask<T>(mask: number, fn: () => T): T {
  const previous = process.umask(mask);
  try {
    return fn();
  } finally {
    process.umask(previous);
  }
}

const modeOf = (p: string): number => fs.statSync(p).mode & 0o777;

function makeEvent(): AuditEvent {
  return {
    timestamp: new Date().toISOString(),
    plugin: 'test',
    action: 'scan',
    target: 'test-target',
    result: 'allowed',
  };
}

function makeReporter(dataDir: string): AIMServerReporter {
  // A batch size above one keeps enqueue from starting a flush, so nothing touches the network.
  return new AIMServerReporter({
    serverUrl: 'https://aim.example.com',
    agentId: 'aim_test123',
    dataDir,
    maxBatchSize: 100,
  });
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-reporter-mode-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

it.skipIf(process.platform === 'win32')('creates report-queue.jsonl at mode 0o600 in a directory at mode 0o700 under umask 022', () => {
  const dataDir = path.join(tmpDir, 'aim-core');
  withUmask(0o022, () => makeReporter(dataDir).enqueue(makeEvent()));

  expect(modeOf(dataDir)).toBe(0o700);
  expect(modeOf(path.join(dataDir, 'report-queue.jsonl'))).toBe(0o600);
});

it.skipIf(process.platform === 'win32')('tightens an existing looser report-queue.jsonl to mode 0o600 and its directory to mode 0o700 when it is opened', () => {
  const dataDir = path.join(tmpDir, 'aim-core');
  const queuePath = path.join(dataDir, 'report-queue.jsonl');
  fs.mkdirSync(dataDir);
  fs.writeFileSync(queuePath, JSON.stringify(makeEvent()) + '\n');
  fs.chmodSync(dataDir, 0o755);
  fs.chmodSync(queuePath, 0o644);

  const reporter = withUmask(0o022, () => makeReporter(dataDir));

  expect(reporter.getQueueLength()).toBe(1);
  expect(modeOf(dataDir)).toBe(0o700);
  expect(modeOf(queuePath)).toBe(0o600);
});

it.skipIf(process.platform === 'win32')('tightens an existing looser report-queue.jsonl to mode 0o600 when it is rewritten', () => {
  const dataDir = path.join(tmpDir, 'aim-core');
  const reporter = makeReporter(dataDir);
  reporter.enqueue(makeEvent());
  const queuePath = path.join(dataDir, 'report-queue.jsonl');
  fs.chmodSync(dataDir, 0o755);
  fs.chmodSync(queuePath, 0o644);

  withUmask(0o022, () => reporter.enqueue(makeEvent()));

  expect(modeOf(dataDir)).toBe(0o700);
  expect(modeOf(queuePath)).toBe(0o600);
});
