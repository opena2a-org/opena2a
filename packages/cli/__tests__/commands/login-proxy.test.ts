/**
 * `opena2a login` behind a proxy: when the AIM server cannot be reached and
 * HTTPS_PROXY applies, the failure names the proxy instead of only "check
 * your network connection". Uses a tmp HOME + OPENA2A_AUTH_FORCE_FILE so no
 * real keychain or auth.json is touched; the AIM host never resolves and the
 * local proxy refuses it, so nothing leaves 127.0.0.1.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';

let TMP_HOME: string;
let proxy: http.Server;
let proxyUrl: string;
let resetEnvProxy: (() => void) | undefined;

beforeAll(async () => {
  proxy = http.createServer((_req, res) => { res.statusCode = 502; res.end(); });
  proxy.on('connect', (_req, socket) => { socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); });
  await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
  proxyUrl = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise((r) => proxy.close(r));
});

beforeEach(() => {
  TMP_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-login-proxy-'));
  vi.stubEnv('HOME', TMP_HOME);
  vi.stubEnv('OPENA2A_AUTH_FORCE_FILE', '1');
  for (const name of ['http_proxy', 'https_proxy', 'no_proxy', 'NO_PROXY']) vi.stubEnv(name, '');
  vi.stubEnv('HTTPS_PROXY', proxyUrl);
});

afterEach(() => {
  resetEnvProxy?.();
  resetEnvProxy = undefined;
  vi.unstubAllEnvs();
  fs.rmSync(TMP_HOME, { recursive: true, force: true });
  vi.restoreAllMocks();
});

async function freshLogin() {
  vi.resetModules();
  ({ resetEnvProxy } = await import('../../src/util/env-proxy.js'));
  return (await import('../../src/commands/login.js')).login;
}

describe('login behind HTTPS_PROXY', () => {
  it('names the proxy when the AIM server is unreachable (text mode)', async () => {
    const login = await freshLogin();
    const errs: string[] = [];
    vi.spyOn(console, 'error').mockImplementation((...a) => { errs.push(a.join(' ')); });
    vi.spyOn(console, 'log').mockImplementation(() => {});

    const code = await login({ server: 'https://aim.scratch.invalid' });

    expect(code).toBe(1);
    const text = errs.join('\n');
    expect(text).toContain('Cannot reach AIM server at https://aim.scratch.invalid');
    expect(text).toContain(proxyUrl);
    expect(text).toContain('HTTPS_PROXY');
  });

  it('reports the proxy in --json mode', async () => {
    const login = await freshLogin();
    const logs: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a) => { logs.push(a.join(' ')); });
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const code = await login({ server: 'https://aim.scratch.invalid', json: true });

    expect(code).toBe(1);
    const parsed = JSON.parse(logs[logs.length - 1]);
    expect(parsed.error).toBe('server_unreachable');
    expect(parsed.proxy).toMatchObject({ url: proxyUrl, variable: 'HTTPS_PROXY' });
    expect(['cli', 'runtime', 'direct']).toContain(parsed.proxy.routing);
  });
});
