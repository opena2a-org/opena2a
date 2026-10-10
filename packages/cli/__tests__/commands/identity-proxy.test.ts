/**
 * `opena2a identity connect` behind a proxy: when the AIM server cannot be
 * reached and HTTPS_PROXY applies, the failure names the proxy and the
 * variable it came from instead of only "Verify the server is running.",
 * and keeps the Detail line. Uses a tmp HOME + OPENA2A_AUTH_FORCE_FILE so no
 * real keychain or auth.json is touched; the AIM host never resolves and the
 * local proxy refuses it, so nothing leaves 127.0.0.1.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';

// The health check runs before the local identity is loaded, so the module
// is never used in this test; a stub keeps the real package out of it.
vi.mock('@opena2a/aim-core', () => ({}));

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
  TMP_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-identity-proxy-'));
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

async function freshIdentity() {
  vi.resetModules();
  ({ resetEnvProxy } = await import('../../src/util/env-proxy.js'));
  return (await import('../../src/commands/identity.js')).identity;
}

describe('identity connect behind HTTPS_PROXY', () => {
  it('names the proxy and its variable when the AIM server is unreachable', async () => {
    const identity = await freshIdentity();
    let stderr = '';
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderr += String(chunk);
      return true;
    });
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    const code = await identity({ subcommand: 'connect', args: ['https://aim.scratch.invalid'], apiKey: 'FAKE-api-key' });

    expect(code).toBe(1);
    expect(stderr).toContain('Cannot connect to AIM server at https://aim.scratch.invalid');
    expect(stderr).toContain(proxyUrl);
    expect(stderr).toContain('HTTPS_PROXY');
    expect(stderr).toContain('Detail:');
    expect(stderr).not.toContain('Verify the server is running.');
  });
});
