/**
 * login --ci fail-fast (issue #189): the device-code flow needs a browser, so
 * in --ci / non-interactive mode `login` must exit non-zero immediately with a
 * clear message instead of blocking on "Waiting for authentication...". Uses a
 * tmp HOME + OPENA2A_AUTH_FORCE_FILE so no real keychain/auth.json is touched
 * and no device-code request reaches the network.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

let TMP_HOME: string;
let originalHome: string | undefined;

beforeEach(() => {
  TMP_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-login-ci-'));
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

async function freshLogin() {
  vi.resetModules();
  return (await import('../../src/commands/login.js')).login;
}

describe('login --ci', () => {
  it('exits non-zero with a clear message (text mode) without blocking', async () => {
    const login = await freshLogin();
    const errs: string[] = [];
    vi.spyOn(console, 'error').mockImplementation((...a) => { errs.push(a.join(' ')); });
    vi.spyOn(console, 'log').mockImplementation(() => {});

    const code = await login({ ci: true });

    expect(code).toBe(1);
    const text = errs.join('\n');
    expect(text).toMatch(/--ci/);
    expect(text).toMatch(/--api-key/);
    // Must NOT have entered the device-code poll.
    expect(text).not.toMatch(/Waiting for authentication/);
  });

  it('emits a structured error in --json mode and exits non-zero', async () => {
    const login = await freshLogin();
    const logs: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a) => { logs.push(a.join(' ')); });
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const code = await login({ ci: true, json: true });

    expect(code).toBe(1);
    const parsed = JSON.parse(logs[logs.length - 1]);
    expect(parsed.error).toBe('interactive_required');
  });

  it('completes promptly (no network poll) in --ci mode', async () => {
    const login = await freshLogin();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const start = Date.now();
    const code = await login({ ci: true });
    expect(code).toBe(1);
    expect(Date.now() - start).toBeLessThan(2000);
  });
});
