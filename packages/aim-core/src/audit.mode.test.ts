import { it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { logEvent } from './audit';

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
const event = { plugin: 'test', action: 'act', target: 't', result: 'allowed' as const };

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-audit-mode-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

it.skipIf(process.platform === 'win32')('creates audit.jsonl at mode 0o600 in a directory at mode 0o700 under umask 022', () => {
  const dataDir = path.join(tmpDir, 'aim-core');
  withUmask(0o022, () => logEvent(dataDir, event));

  expect(modeOf(dataDir)).toBe(0o700);
  expect(modeOf(path.join(dataDir, 'audit.jsonl'))).toBe(0o600);
});

it.skipIf(process.platform === 'win32')('tightens an existing looser audit.jsonl to mode 0o600 and its directory to mode 0o700', () => {
  const dataDir = path.join(tmpDir, 'aim-core');
  const filePath = path.join(dataDir, 'audit.jsonl');
  fs.mkdirSync(dataDir);
  fs.writeFileSync(filePath, '');
  fs.chmodSync(dataDir, 0o755);
  fs.chmodSync(filePath, 0o644);

  withUmask(0o022, () => logEvent(dataDir, event));

  expect(modeOf(dataDir)).toBe(0o700);
  expect(modeOf(filePath)).toBe(0o600);
});
