import { it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createIdentity } from './identity';

// `fs` is replaced, for this file's whole module graph (including identity.ts), by a plain
// mutable copy of the real module. Every function on the copy is the real implementation;
// the copy only exists so that each case can swap the chmod family for inert functions with
// vi.spyOn (the native ESM namespace of a builtin is not spy-able) and restore them afterwards.
vi.mock('fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs')>();
  return { ...actual };
});

/** Replace chmodSync, fchmodSync, chmod and fchmod with functions that change nothing. */
function makeChmodsInert(): void {
  vi.spyOn(fs, 'chmodSync').mockImplementation(() => undefined);
  vi.spyOn(fs, 'fchmodSync').mockImplementation(() => undefined);
  vi.spyOn(fs, 'chmod').mockImplementation((_path, _mode, callback) => {
    callback(null);
  });
  vi.spyOn(fs, 'fchmod').mockImplementation((_fd, _mode, callback) => {
    callback(null);
  });
}

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

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-mode-test-'));
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

it('QGF-304.AC1 creates identity.json at 0o600 under umask 022 with every chmod inert', () => {
  makeChmodsInert();
  try {
    withUmask(0o022, () => createIdentity(tmpDir, 'test-agent'));
  } finally {
    vi.restoreAllMocks();
  }

  expect(modeOf(path.join(tmpDir, 'identity.json'))).toBe(0o600);
});

it('QGF-304.AC2 creates identity.json at 0o600 under umask 000 with every chmod inert and leaves no tmp file', () => {
  makeChmodsInert();
  try {
    withUmask(0o000, () => createIdentity(tmpDir, 'test-agent'));
  } finally {
    vi.restoreAllMocks();
  }

  expect(modeOf(path.join(tmpDir, 'identity.json'))).toBe(0o600);
  const leftovers = fs.readdirSync(tmpDir).filter((name) => name.startsWith('identity.json.tmp.'));
  expect(leftovers).toEqual([]);
});
