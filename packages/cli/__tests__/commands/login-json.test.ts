/**
 * login --json (issue #418): without --ci the device-code flow runs, and stdout
 * must still hold exactly one JSON value -- the final result. The progress
 * document carrying the code to enter goes to stderr. AimClient is stubbed and
 * the browser launch is mocked, so nothing leaves the process; a tmp HOME +
 * OPENA2A_AUTH_FORCE_FILE keeps the real keychain and auth.json untouched.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

vi.mock('node:child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:child_process')>()),
  exec: vi.fn(),
}));

let TMP_HOME: string;

beforeEach(() => {
  TMP_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-login-json-'));
  vi.stubEnv('HOME', TMP_HOME);
  vi.stubEnv('OPENA2A_AUTH_FORCE_FILE', '1');
});

afterEach(() => {
  vi.unstubAllEnvs();
  fs.rmSync(TMP_HOME, { recursive: true, force: true });
  vi.restoreAllMocks();
});

async function loadLogin() {
  vi.resetModules();
  const { AimClient, AimServerError } = await import('../../src/util/aim-client.js');
  vi.spyOn(AimClient.prototype, 'health').mockResolvedValue({ status: 'ok' });
  vi.spyOn(AimClient.prototype, 'requestDeviceCode').mockResolvedValue({
    deviceCode: 'dev-code',
    userCode: 'ABCD-EFGH',
    verificationUri: 'https://aim.scratch.invalid/device',
    verificationUriComplete: 'https://aim.scratch.invalid/device?code=ABCD-EFGH',
    expiresIn: 60,
    interval: 0.001,
  } as any);
  const { login } = await import('../../src/commands/login.js');
  return { login, AimClient, AimServerError };
}

function captureStreams() {
  const out: string[] = [];
  const err: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a) => { out.push(a.join(' ')); });
  vi.spyOn(console, 'error').mockImplementation((...a) => { err.push(a.join(' ')); });
  return { out, err };
}

describe('login --json without --ci', () => {
  it('prints one JSON value on stdout when login succeeds', async () => {
    const { login, AimClient } = await loadLogin();
    vi.spyOn(AimClient.prototype, 'pollDeviceToken').mockResolvedValue({
      accessToken: 'at',
      refreshToken: 'rt',
      expiresIn: 3600,
      tokenType: 'Bearer',
    } as any);
    const { out, err } = captureStreams();

    const code = await login({ server: 'https://aim.scratch.invalid', json: true });

    expect(code).toBe(0);
    const parsed = JSON.parse(out.join('\n'));
    expect(parsed.status).toBe('authenticated');
    // The code to enter is still shown, on stderr.
    expect(err.join('\n')).toContain('ABCD-EFGH');
  });

  it('prints one JSON value on stdout when login is denied', async () => {
    const { login, AimClient, AimServerError } = await loadLogin();
    const denied = new AimServerError('denied', 400);
    (denied as any).oauthError = 'access_denied';
    vi.spyOn(AimClient.prototype, 'pollDeviceToken').mockRejectedValue(denied);
    const { out } = captureStreams();

    const code = await login({ server: 'https://aim.scratch.invalid', json: true });

    expect(code).toBe(1);
    const parsed = JSON.parse(out.join('\n'));
    expect(parsed.error).toBe('denied');
  });
});
