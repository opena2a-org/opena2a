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
  routeThroughEnvProxy,
  fetchWithEnvProxy,
} from '../../src/util/env-proxy.js';
import { AimClient, AimServerError } from '../../src/util/aim-client.js';

const AIM_HOST = 'aim.scratch.invalid';

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

  it('removes user name and password from a proxy URL without a scheme or with a / in the password', () => {
    expect(redactProxyUrl('alice:FAKE-PASS@proxy.corp:8080')).toBe('proxy.corp:8080');
    expect(redactProxyUrl('http://alice:FAKE/PASS@proxy.corp:8080')).toBe('http://proxy.corp:8080');
    expect(redactProxyUrl('http://alice:1234/FAKE@proxy.corp:8080')).toBe('http://proxy.corp:8080');
    expect(envProxyFor('https://aim.example.com', { HTTPS_PROXY: 'alice:FAKE-PASS@proxy.corp:8080' })?.url)
      .toBe('proxy.corp:8080');
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
  const proxyAuth: Array<string | undefined> = [];

  beforeAll(async () => {
    aim = http.createServer((req, res) => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/echo') {
        let body = '';
        req.on('data', (c) => { body += c; });
        req.on('end', () => res.end(JSON.stringify({ method: req.method, body, type: req.headers['content-type'] })));
        return;
      }
      res.end(req.url === '/health' ? JSON.stringify({ status: 'ok' }) : '{}');
    });
    await new Promise<void>((r) => aim.listen(0, '127.0.0.1', r));
    aimPort = (aim.address() as AddressInfo).port;

    // Knows AIM_HOST; refuses every other destination with 502. Its own
    // upstream requests use a private agent so they never loop through itself.
    const direct = new http.Agent();
    proxy = http.createServer((req, res) => {
      proxyLog.push(`${req.method} ${req.url}`);
      proxyAuth.push(req.headers['proxy-authorization']);
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
      proxyAuth.push(req.headers['proxy-authorization']);
      if (req.url === `hang.${AIM_HOST}:443`) {
        // Never answers; lets go once the client closes its side.
        socket.on('end', () => socket.destroy());
        return;
      }
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
    proxy.closeAllConnections();
    await new Promise((r) => aim.close(r));
    await new Promise((r) => proxy.close(r));
  });

  afterEach(() => {
    resetEnvProxy();
    vi.unstubAllEnvs();
    proxyLog.length = 0;
    proxyAuth.length = 0;
  });

  function useProxyEnv(): void {
    for (const name of ['http_proxy', 'https_proxy', 'no_proxy', 'NO_PROXY', 'NODE_USE_ENV_PROXY']) vi.stubEnv(name, '');
    vi.stubEnv('HTTP_PROXY', proxyUrl);
    vi.stubEnv('HTTPS_PROXY', proxyUrl);
  }

  it('reaches AIM through HTTP_PROXY when direct access is impossible', async () => {
    useProxyEnv();
    const client = new AimClient(`http://${AIM_HOST}:${aimPort}`, { timeoutMs: 5000 });
    await expect(client.health()).resolves.toEqual({ status: 'ok' });
    expect(proxyLog.length).toBeGreaterThan(0);
    expect(proxyLog.every((line) => line.includes(AIM_HOST))).toBe(true);
  });

  it('sends https requests to the proxy and names it when the proxy refuses', async () => {
    useProxyEnv();
    const client = new AimClient(`https://${AIM_HOST}`, { timeoutMs: 5000 });
    const err = await client.health().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(AimServerError);
    expect(proxyLog).toContain(`CONNECT ${AIM_HOST}:443`);
    expect((err as AimServerError).proxyRoute).toEqual({ proxy: { url: proxyUrl, variable: 'HTTPS_PROXY' }, routing: 'cli' });
    expect((err as AimServerError).message).toContain(proxyUrl);
  });

  describe('on a runtime without built-in proxy support', () => {
    // Stands in for Node.js releases without http.setGlobalProxyFromEnv
    // (20.x, 22.x and 24.x before 24.21 among them): the CLI connects to the
    // proxy itself. On such a runtime these run the real path.
    function withoutBuiltInSupport(): void {
      resetEnvProxy({ builtInProxySupport: false });
      useProxyEnv();
    }

    it('reaches AIM through HTTP_PROXY with its own connection to the proxy', async () => {
      withoutBuiltInSupport();
      const client = new AimClient(`http://${AIM_HOST}:${aimPort}`, { timeoutMs: 5000 });
      await expect(client.health()).resolves.toEqual({ status: 'ok' });
      expect(proxyLog).toEqual([`GET http://${AIM_HOST}:${aimPort}/health`]);
      expect(proxyAuth).toEqual([undefined]);
    });

    it('connects to the proxy itself even when NODE_USE_ENV_PROXY=1 is set', async () => {
      // Releases without http.setGlobalProxyFromEnv may ignore the variable.
      withoutBuiltInSupport();
      vi.stubEnv('NODE_USE_ENV_PROXY', '1');
      const client = new AimClient(`http://${AIM_HOST}:${aimPort}`, { timeoutMs: 5000 });
      await expect(client.health()).resolves.toEqual({ status: 'ok' });
      expect(proxyLog).toEqual([`GET http://${AIM_HOST}:${aimPort}/health`]);
    });

    it('does not turn on a proxy for the rest of the process', async () => {
      withoutBuiltInSupport();
      expect(routeThroughEnvProxy(`http://${AIM_HOST}:${aimPort}`)?.routing).toBe('cli');
      await expect(globalThis.fetch(`http://${AIM_HOST}:${aimPort}/health`)).rejects.toThrow();
      expect(proxyLog).toEqual([]);
    });

    it('sends a request body and its headers through the proxy', async () => {
      withoutBuiltInSupport();
      const url = `http://${AIM_HOST}:${aimPort}/echo`;
      const res = await fetchWithEnvProxy(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId: 'opena2a-cli' }),
      }, routeThroughEnvProxy(url));
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ method: 'POST', body: '{"clientId":"opena2a-cli"}', type: 'application/json' });
    });

    it('opens a CONNECT tunnel for https and names the proxy and its answer when it refuses', async () => {
      withoutBuiltInSupport();
      const client = new AimClient(`https://${AIM_HOST}`, { timeoutMs: 5000 });
      const err = await client.health().then(() => null, (e: unknown) => e);
      expect(err).toBeInstanceOf(AimServerError);
      expect(proxyLog).toEqual([`CONNECT ${AIM_HOST}:443`]);
      expect((err as AimServerError).proxyRoute).toEqual({ proxy: { url: proxyUrl, variable: 'HTTPS_PROXY' }, routing: 'cli' });
      expect((err as AimServerError).message).toContain(proxyUrl);
      expect((err as AimServerError).message).toContain('502');
    });

    it('sends the proxy user name and password as Proxy-Authorization and never prints them', async () => {
      withoutBuiltInSupport();
      const withCreds = proxyUrl.replace('http://', 'http://alice:' + 's3cret' + '@');
      vi.stubEnv('HTTP_PROXY', withCreds);
      vi.stubEnv('HTTPS_PROXY', withCreds);

      const plain = new AimClient(`http://${AIM_HOST}:${aimPort}`, { timeoutMs: 5000 });
      await expect(plain.health()).resolves.toEqual({ status: 'ok' });

      const secure = new AimClient(`https://${AIM_HOST}`, { timeoutMs: 5000 });
      const err = await secure.health().then(() => null, (e: unknown) => e);
      expect(err).toBeInstanceOf(AimServerError);
      const expected = `Basic ${Buffer.from('alice:s3cret').toString('base64')}`;
      expect(proxyAuth).toEqual([expected, expected]);
      expect((err as AimServerError).message).toContain(proxyUrl);
      expect((err as AimServerError).message).not.toMatch(/alice|s3cret/);
    });

    it('times out and names the proxy when the proxy never answers', async () => {
      withoutBuiltInSupport();
      const client = new AimClient(`https://hang.${AIM_HOST}`, { timeoutMs: 300 });
      const err = await client.health().then(() => null, (e: unknown) => e);
      expect(err).toBeInstanceOf(AimServerError);
      expect((err as AimServerError).message).toMatch(/timed out after 300ms/);
      expect((err as AimServerError).message).toContain(proxyUrl);
    });

    it('goes direct, and says so, when the proxy URL is not an http or https URL', async () => {
      withoutBuiltInSupport();
      vi.stubEnv('HTTPS_PROXY', 'socks5://127.0.0.1:1080');
      const client = new AimClient(`https://${AIM_HOST}`, { timeoutMs: 5000 });
      const err = await client.health().then(() => null, (e: unknown) => e);
      expect((err as AimServerError).proxyRoute?.routing).toBe('direct');
      expect((err as AimServerError).message).toMatch(/went direct/);
      expect(proxyLog).toEqual([]);
    });
  });

  it('never prints the password of a proxy URL without a scheme', async () => {
    useProxyEnv();
    vi.stubEnv('HTTPS_PROXY', 'alice:FAKE-PASS@proxy.corp:8080');
    const client = new AimClient(`https://${AIM_HOST}`, { timeoutMs: 5000 });
    const err = await client.health().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(AimServerError);
    expect((err as AimServerError).proxyRoute?.proxy.url).toBe('proxy.corp:8080');
    expect((err as AimServerError).message).toContain('proxy.corp:8080');
    expect((err as AimServerError).message).not.toMatch(/alice|FAKE-PASS/);
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
