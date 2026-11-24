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

it('creates identity.json at 0o600 under umask 022 with every chmod inert', () => {
  makeChmodsInert();
  try {
    withUmask(0o022, () => createIdentity(tmpDir, 'test-agent'));
  } finally {
    vi.restoreAllMocks();
  }

  expect(modeOf(path.join(tmpDir, 'identity.json'))).toBe(0o600);
});

it('creates identity.json at 0o600 under umask 000 with every chmod inert and leaves no tmp file', () => {
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

it('never calls chmod on the identity file: the mode comes from the creating open alone', () => {
  const chmod = vi.spyOn(fs, 'chmodSync');
  const fchmod = vi.spyOn(fs, 'fchmodSync');

  withUmask(0o022, () => createIdentity(tmpDir, 'test-agent'));

  expect(chmod).not.toHaveBeenCalled();
  expect(fchmod).not.toHaveBeenCalled();
  expect(modeOf(path.join(tmpDir, 'identity.json'))).toBe(0o600);
});

it('refuses to write the key through a symlink planted at the temp path after the stale-file removal', () => {
  const decoy = path.join(tmpDir, 'decoy.txt');
  fs.writeFileSync(decoy, 'untouched');
  const realRmSync = fs.rmSync;
  // Simulate a racing process: right after the stale temp file is removed, a symlink to
  // another file appears at the temp path. An exclusive create must fail rather than follow it.
  vi.spyOn(fs, 'rmSync').mockImplementation((p, opts) => {
    realRmSync(p, opts);
    if (String(p).includes('identity.json.tmp.')) fs.symlinkSync(decoy, p);
  });

  expect(() => createIdentity(tmpDir, 'test-agent')).toThrow(/EEXIST/);
  vi.restoreAllMocks();

  expect(fs.readFileSync(decoy, 'utf-8')).toBe('untouched');
  expect(fs.existsSync(path.join(tmpDir, 'identity.json'))).toBe(false);
});
