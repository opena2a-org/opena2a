/**
 * setup --ci without credentials (issue #453): browser login is unavailable in
 * --ci mode, so `setup` must print only the login refusal and exit non-zero,
 * never announce that it is launching a browser login. Uses a tmp HOME +
 * OPENA2A_AUTH_FORCE_FILE so no real keychain/auth.json is touched.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

let TMP_HOME: string;
let originalHome: string | undefined;

beforeEach(() => {
  TMP_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-setup-ci-'));
  originalHome = process.env.HOME;
  process.env.HOME = TMP_HOME;
  process.env.OPENA2A_AUTH_FORCE_FILE = '1';
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  delete process.env.OPENA2A_AUTH_FORCE_FILE;
  fs.rmSync(TMP_HOME, { recursive: true, force: true });
  vi.restoreAllMocks();
});

async function freshSetup() {
  vi.resetModules();
  return (await import('../../src/commands/setup.js')).setup;
}

describe('setup --ci without credentials', () => {
  it('prints the login refusal only and exits non-zero', async () => {
    const setup = await freshSetup();
    const out: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      out.push(String(chunk));
      return true;
    });
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      out.push(String(chunk));
      return true;
    });
    vi.spyOn(console, 'error').mockImplementation((...a) => { out.push(a.join(' ')); });
    vi.spyOn(console, 'log').mockImplementation((...a) => { out.push(a.join(' ')); });

    const code = await setup({ targetDir: TMP_HOME, ci: true });

    expect(code).toBe(1);
    const text = out.join('\n');
    expect(text).toMatch(/Browser login is unavailable in --ci mode/);
    expect(text).not.toMatch(/Launching browser login/);
    expect(text).not.toMatch(/Press Ctrl\+C/);
  });
});
