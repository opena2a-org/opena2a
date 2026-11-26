import { it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { logVaultEvent } from './audit';

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
const event = {
  agentId: 'aim_test123',
  namespace: 'github',
  operation: 'resolve' as const,
  result: 'granted' as const,
};

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-vault-audit-mode-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

it.skipIf(process.platform === 'win32')('creates vault-audit.jsonl at mode 0o600 in a directory at mode 0o700 under umask 022', () => {
  const vaultDir = path.join(tmpDir, 'vault');
  withUmask(0o022, () => logVaultEvent(vaultDir, event));

  expect(modeOf(vaultDir)).toBe(0o700);
  expect(modeOf(path.join(vaultDir, 'vault-audit.jsonl'))).toBe(0o600);
});

it.skipIf(process.platform === 'win32')('tightens an existing looser vault-audit.jsonl to mode 0o600 and its directory to mode 0o700', () => {
  const vaultDir = path.join(tmpDir, 'vault');
  const filePath = path.join(vaultDir, 'vault-audit.jsonl');
  fs.mkdirSync(vaultDir);
  fs.writeFileSync(filePath, '');
  fs.chmodSync(vaultDir, 0o755);
  fs.chmodSync(filePath, 0o644);

  withUmask(0o022, () => logVaultEvent(vaultDir, event));

  expect(modeOf(vaultDir)).toBe(0o700);
  expect(modeOf(filePath)).toBe(0o600);
});
