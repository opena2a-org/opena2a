/**
 * AIM requests honour HTTPS_PROXY / HTTP_PROXY / NO_PROXY, or the failure
 * names the proxy. The AIM host `aim.scratch.invalid` never resolves, so a
 * request that ignores the proxy cannot reach the stub: only the local proxy
 * maps that host to it. Nothing here leaves 127.0.0.1.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import * as http from 'node:http';
import * as net from 'node:net';
import type { AddressInfo } from 'node:net';
import {
  envProxyFor,
  isNoProxyHost,
  redactProxyUrl,
  describeProxyRoute,
  resetEnvProxy,
} from '../../src/util/env-proxy.js';
import { AimClient, AimServerError } from '../../src/util/aim-client.js';

const AIM_HOST = 'aim.scratch.invalid';
const hasBuiltInProxy =
  typeof (http as unknown as { setGlobalProxyFromEnv?: unknown }).setGlobalProxyFromEnv === 'function';

describe('envProxyFor', () => {
  it('uses HTTPS_PROXY for https targets and HTTP_PROXY for http targets', () => {
    const env = { HTTPS_PROXY: 'http://secure-proxy:3128', HTTP_PROXY: 'http://plain-proxy:3128' };
    expect(envProxyFor('https://aim.example.com', env)).toEqual({ url: 'http://secure-proxy:3128', variable: 'HTTPS_PROXY' });
    expect(envProxyFor('http://aim.example.com', env)).toEqual({ url: 'http://plain-proxy:3128', variable: 'HTTP_PROXY' });
  });

  it('prefers the lower-case variable, as curl and Node do', () => {
    const env = { https_proxy: 'http://lower:1', HTTPS_PROXY: 'http://upper:2' };
    expect(envProxyFor('https://aim.example.com', env)?.variable).toBe('https_proxy');
  });

  it('returns null when no proxy variable is set for the scheme', () => {
    expect(envProxyFor('https://aim.example.com', { HTTP_PROXY: 'http://plain-proxy:3128' })).toBeNull();
    expect(envProxyFor('https://aim.example.com', {})).toBeNull();
  });

  it('removes user name and password from the printed proxy URL', () => {
    const proxyWithUser = 'http://alice:' + 's3cret' + '@proxy.corp:8080';
    const proxy = envProxyFor('https://aim.example.com', { HTTPS_PROXY: proxyWithUser });
    expect(proxy?.url).toBe('http://proxy.corp:8080');
    expect(redactProxyUrl(proxyWithUser + '/')).not.toMatch(/alice|s3cret/);
  });

  it('honours NO_PROXY exact hosts, domain suffixes, ports and *', () => {
    const env = { HTTPS_PROXY: 'http://proxy:3128', NO_PROXY: 'internal.corp, .lan,aim.example.com:8443' };
    expect(envProxyFor('https://internal.corp', env)).toBeNull();
    expect(envProxyFor('https://aim.lan', env)).toBeNull();
    expect(envProxyFor('https://aim.example.com:8443', env)).toBeNull();
    expect(envProxyFor('https://aim.example.com', env)).not.toBeNull();
    expect(envProxyFor('https://notinternal.corp', env)).not.toBeNull();
    expect(isNoProxyHost('anything.example', '443', { NO_PROXY: '*' })).toBe(true);
    expect(isNoProxyHost('api.example.com', '443', { no_proxy: '*.example.com' })).toBe(true);
  });

  it('never sends loopback hosts through the proxy, so a local AIM keeps working', () => {
    const env = { HTTP_PROXY: 'http://proxy:3128', HTTPS_PROXY: 'http://proxy:3128' };
    expect(envProxyFor('http://localhost:8080', env)).toBeNull();
    expect(envProxyFor('http://127.0.0.1:8080', env)).toBeNull();
    expect(envProxyFor('http://[::1]:8080', env)).toBeNull();
  });
});

describe('describeProxyRoute', () => {
  const proxy = { url: 'http://proxy.corp:3128', variable: 'HTTPS_PROXY' };

  it('names the proxy and the variable when the request went through it', () => {
    const line = describeProxyRoute({ proxy, routing: 'cli' }, 'https://aim.example.com');
    expect(line).toContain('http://proxy.corp:3128');
    expect(line).toContain('HTTPS_PROXY');
    expect(line).toContain('aim.example.com');
  });

  it('says the request went direct, with the Node.js version, when the runtime cannot use the proxy', () => {
    const line = describeProxyRoute({ proxy, routing: 'direct' }, 'https://aim.example.com');
    expect(line).toContain('http://proxy.corp:3128');
    expect(line).toContain(process.version);
    expect(line).toMatch(/went direct/);
  });
});

describe('AimClient behind a proxy', () => {
  let aim: http.Server;
  let proxy: http.Server;
  let aimPort: number;
  let proxyUrl: string;
  const proxyLog: string[] = [];

  beforeAll(async () => {
    aim = http.createServer((req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(req.url === '/health' ? JSON.stringify({ status: 'ok' }) : '{}');
    });
    await new Promise<void>((r) => aim.listen(0, '127.0.0.1', r));
    aimPort = (aim.address() as AddressInfo).port;

    // Knows AIM_HOST; refuses every other destination with 502. Its own
    // upstream requests use a private agent so they never loop through itself.
    const direct = new http.Agent();
    proxy = http.createServer((req, res) => {
      proxyLog.push(`${req.method} ${req.url}`);
      const target = new URL(req.url ?? '');
      if (target.hostname !== AIM_HOST) { res.statusCode = 502; res.end(); return; }
      const upstream = http.request(
        { host: '127.0.0.1', port: aimPort, method: req.method, path: target.pathname + target.search, headers: req.headers, agent: direct },
        (ur) => { res.writeHead(ur.statusCode ?? 502, ur.headers); ur.pipe(res); },
      );
      req.pipe(upstream);
    });
    proxy.on('connect', (req, socket, head) => {
      proxyLog.push(`CONNECT ${req.url}`);
      if (req.url !== `${AIM_HOST}:${aimPort}`) { socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); return; }
      const upstream = net.connect(aimPort, '127.0.0.1', () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        upstream.write(head);
        upstream.pipe(socket);
        socket.pipe(upstream);
      });
      upstream.on('error', () => socket.destroy());
    });
    await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
    proxyUrl = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise((r) => aim.close(r));
    await new Promise((r) => proxy.close(r));
  });

  afterEach(() => {
    resetEnvProxy();
    vi.unstubAllEnvs();
    proxyLog.length = 0;
  });

  function useProxyEnv(): void {
    for (const name of ['http_proxy', 'https_proxy', 'no_proxy', 'NO_PROXY']) vi.stubEnv(name, '');
    vi.stubEnv('HTTP_PROXY', proxyUrl);
    vi.stubEnv('HTTPS_PROXY', proxyUrl);
  }

  it.runIf(hasBuiltInProxy)('reaches AIM through HTTP_PROXY when direct access is impossible', async () => {
    useProxyEnv();
    const client = new AimClient(`http://${AIM_HOST}:${aimPort}`, { timeoutMs: 5000 });
    await expect(client.health()).resolves.toEqual({ status: 'ok' });
    expect(proxyLog.length).toBeGreaterThan(0);
    expect(proxyLog.every((line) => line.includes(AIM_HOST))).toBe(true);
  });

  it.runIf(hasBuiltInProxy)('sends https requests to the proxy and names it when the proxy refuses', async () => {
    useProxyEnv();
    const client = new AimClient(`https://${AIM_HOST}`, { timeoutMs: 5000 });
    const err = await client.health().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(AimServerError);
    expect(proxyLog).toContain(`CONNECT ${AIM_HOST}:443`);
    expect((err as AimServerError).proxyRoute).toEqual({ proxy: { url: proxyUrl, variable: 'HTTPS_PROXY' }, routing: 'cli' });
    expect((err as AimServerError).message).toContain(proxyUrl);
  });

  it.skipIf(hasBuiltInProxy)('names the proxy and says the request went direct on runtimes without proxy support', async () => {
    useProxyEnv();
    const client = new AimClient(`https://${AIM_HOST}`, { timeoutMs: 5000 });
    const err = await client.health().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(AimServerError);
    expect((err as AimServerError).proxyRoute?.proxy.url).toBe(proxyUrl);
    expect((err as AimServerError).message).toContain(proxyUrl);
  });

  it('leaves requests alone when NO_PROXY exempts the AIM host', async () => {
    useProxyEnv();
    vi.stubEnv('NO_PROXY', AIM_HOST);
    const client = new AimClient(`https://${AIM_HOST}`, { timeoutMs: 5000 });
    const err = await client.health().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(AimServerError);
    expect((err as AimServerError).proxyRoute).toBeUndefined();
    expect(proxyLog).toEqual([]);
  });
});
