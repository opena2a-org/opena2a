/**
 * Proxy settings from the environment (HTTPS_PROXY, HTTP_PROXY, NO_PROXY)
 * for the CLI's own HTTP requests.
 *
 * Node's global fetch ignores these variables unless the runtime is told to
 * honour them. On a host whose only route out is a proxy, a request that
 * ignores them goes direct and fails with a generic network error. This module
 * turns on Node's built-in proxy support when the runtime offers it
 * (`http.setGlobalProxyFromEnv`). On a runtime without it the CLI connects to
 * the proxy itself: an absolute-form request for an http target, a CONNECT
 * tunnel for an https one. Every failure line can name the proxy that applies.
 */

import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as tls from 'node:tls';

export interface EnvProxy {
  /** Proxy URL with any user name and password removed; safe to print. */
  url: string;
  /** The environment variable the proxy URL came from. */
  variable: string;
}

/**
 * How a request reaches the proxy:
 * - `cli`: the CLI sends it there, through Node's built-in proxy support
 *   turned on for this process or, on a runtime without that support, through
 *   its own connection to the proxy (see fetchWithEnvProxy).
 * - `direct`: the proxy URL is not an http:// or https:// URL the CLI can use.
 */
export type ProxyRouting = 'cli' | 'direct';

export interface ProxyRoute {
  proxy: EnvProxy;
  routing: ProxyRouting;
}

type Env = Record<string, string | undefined>;

/**
 * Remove user name and password from a proxy URL before it is printed. They
 * run from the scheme, when the value has one, to the last '@': a value
 * without a scheme (user:password@host:port, a form curl accepts) parses
 * with the user name as its scheme, and an unencoded '/', '?' or '#' in a
 * password ends the host part before the '@'.
 */
export function redactProxyUrl(raw: string): string {
  // `new URL` ignores surrounding whitespace, so the scheme test must too, or
  // an `http://` URL with a leading space would miss it and be printed
  // without its scheme.
  const value = raw.trim();
  const scheme = /^[a-z][a-z0-9+.-]*:\/\//i.exec(value)?.[0] ?? '';
  const rest = value.slice(scheme.length);
  const hostPart = rest.slice(rest.lastIndexOf('@') + 1);
  if (!scheme) return hostPart.replace(/\/$/, '');
  try {
    return new URL(scheme + hostPart).toString().replace(/\/$/, '');
  } catch {
    return (scheme + hostPart).replace(/\/$/, '');
  }
}

/** Loopback hosts never go through a proxy, so a local AIM keeps working. */
const LOOPBACK_NO_PROXY = 'localhost,127.0.0.1';

function isLoopback(host: string): boolean {
  return host === 'localhost' || host === '::1' || /^127(\.\d{1,3}){3}$/.test(host);
}

/**
 * Whether this host and port skip the proxy: a loopback host, or a match in
 * NO_PROXY (or no_proxy).
 */
export function isNoProxyHost(hostname: string, port: string, env: Env = process.env): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (isLoopback(host)) return true;
  const list = env.no_proxy || env.NO_PROXY;
  if (!list) return false;
  for (const raw of list.split(/[\s,]+/)) {
    const entry = raw.trim().toLowerCase();
    if (!entry) continue;
    if (entry === '*') return true;
    const m = /^(\[[^\]]*\]|[^:]+)(?::(\d+))?$/.exec(entry);
    const entryHost = (m ? m[1] : entry).replace(/^\[|\]$/g, '');
    const entryPort = m?.[2];
    if (entryPort && entryPort !== port) continue;
    if (entryHost === host) return true;
    const suffix = entryHost.startsWith('*.') ? entryHost.slice(1)
      : entryHost.startsWith('.') ? entryHost : null;
    if (suffix && (host.endsWith(suffix) || host === suffix.slice(1))) return true;
  }
  return false;
}

/**
 * The proxy the environment names for a request to `target`, or null when no
 * proxy variable is set for its scheme or NO_PROXY exempts the host.
 * Lower-case variables win, as in curl and Node's built-in support.
 */
export function envProxyFor(target: string | URL, env: Env = process.env): EnvProxy | null {
  let url: URL;
  try {
    url = typeof target === 'string' ? new URL(target) : target;
  } catch {
    return null;
  }
  const names = url.protocol === 'https:' ? ['https_proxy', 'HTTPS_PROXY']
    : url.protocol === 'http:' ? ['http_proxy', 'HTTP_PROXY']
    : [];
  const variable = names.find((n) => env[n]);
  if (!variable) return null;
  const port = url.port || (url.protocol === 'https:' ? '443' : '80');
  if (isNoProxyHost(url.hostname, port, env)) return null;
  return { url: redactProxyUrl(env[variable] as string), variable };
}

type SetGlobalProxyFromEnv = (env?: Env) => () => void;

let restoreGlobalProxy: (() => void) | null = null;

/** False only while a test stands in for a runtime without built-in support. */
let builtInSupportAllowed = true;

/**
 * Routes the CLI carries over its own connection to the proxy, mapped to the
 * proxy URL as configured. That URL may hold a user name and password, so it
 * stays here and never on the route object, which is printed and serialised.
 */
const ownConnection = new WeakMap<ProxyRoute, URL>();

function parseHttpProxyUrl(raw: string): URL | null {
  try {
    const u = new URL(raw);
    return (u.protocol === 'http:' || u.protocol === 'https:') && u.hostname ? u : null;
  } catch {
    return null;
  }
}

/**
 * Make requests to `target` go through the proxy the environment names for
 * it. Returns null when no proxy applies, otherwise the proxy and how the
 * request reaches it. Turning on Node's built-in support affects every
 * fetch and http(s) request in this process and applies NO_PROXY (plus
 * loopback hosts) per request.
 */
export function routeThroughEnvProxy(target: string | URL, env: Env = process.env): ProxyRoute | null {
  const proxy = envProxyFor(target, env);
  if (!proxy) return null;
  const proxyUrl = parseHttpProxyUrl(env[proxy.variable] as string);
  if (!proxyUrl) return { proxy, routing: 'direct' };
  if (restoreGlobalProxy) return { proxy, routing: 'cli' };

  const setGlobal = builtInSupportAllowed
    ? (http as unknown as { setGlobalProxyFromEnv?: SetGlobalProxyFromEnv }).setGlobalProxyFromEnv
    : undefined;
  if (typeof setGlobal === 'function') {
    const noProxy = [env.no_proxy || env.NO_PROXY, LOOPBACK_NO_PROXY].filter(Boolean).join(',');
    try {
      restoreGlobalProxy = setGlobal({ ...env, no_proxy: noProxy, NO_PROXY: noProxy });
      return { proxy, routing: 'cli' };
    } catch {
      // Node rejected the configuration; the CLI connects to the proxy itself.
    }
  }
  // Without http.setGlobalProxyFromEnv the CLI does not rely on
  // NODE_USE_ENV_PROXY either: releases that predate it ignore the variable.
  const route: ProxyRoute = { proxy, routing: 'cli' };
  ownConnection.set(route, proxyUrl);
  return route;
}

/**
 * Undo routeThroughEnvProxy for this process. With
 * `builtInProxySupport: false`, behave as a runtime without
 * http.setGlobalProxyFromEnv until the next reset. Used by tests.
 */
export function resetEnvProxy(options: { builtInProxySupport?: boolean } = {}): void {
  restoreGlobalProxy?.();
  restoreGlobalProxy = null;
  builtInSupportAllowed = options.builtInProxySupport ?? true;
}

/**
 * fetch() for `url` along `route`, the result of routeThroughEnvProxy for it.
 * The global fetch carries the request unless the CLI has to connect to the
 * proxy itself. That transport answers redirects with the 3xx response
 * instead of following them.
 */
export function fetchWithEnvProxy(
  url: string,
  init: RequestInit,
  route: ProxyRoute | null | undefined,
): Promise<Response> {
  const proxyUrl = route ? ownConnection.get(route) : undefined;
  if (!proxyUrl) return globalThis.fetch(url, init);
  return fetchThroughProxy(new URL(url), proxyUrl, init);
}

function portOf(u: URL): number {
  return Number(u.port || (u.protocol === 'https:' ? 443 : 80));
}

/** Host name without the brackets URL keeps around an IPv6 address. */
function bareHost(u: URL): string {
  return u.hostname.replace(/^\[|\]$/g, '');
}

function tlsServerName(host: string): string | undefined {
  return net.isIP(host) ? undefined : host;
}

/** A socket to the proxy itself, never through a global agent or proxy. */
function connectToProxy(proxy: URL): net.Socket {
  const host = bareHost(proxy);
  const port = portOf(proxy);
  return proxy.protocol === 'https:'
    ? tls.connect({ host, port, servername: tlsServerName(host), ALPNProtocols: ['http/1.1'] })
    : net.connect({ host, port });
}

function proxyAuthorization(proxy: URL): Record<string, string> {
  if (!proxy.username && !proxy.password) return {};
  const credentials = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
  return { 'proxy-authorization': `Basic ${Buffer.from(credentials).toString('base64')}` };
}

function abortError(): Error {
  const err = new Error('This operation was aborted');
  err.name = 'AbortError';
  return err;
}

/**
 * One request through `proxy` over a connection the CLI opens itself. Errors
 * take fetch's shape: AbortError when `init.signal` aborts, otherwise
 * TypeError('fetch failed') with the reason in `cause`.
 */
function fetchThroughProxy(target: URL, proxy: URL, init: RequestInit): Promise<Response> {
  const method = (init.method ?? 'GET').toUpperCase();
  const headers: Record<string, string> = {};
  new Headers(init.headers).forEach((value, name) => { headers[name] = value; });
  const body = init.body ?? undefined;
  if (body !== undefined && typeof body !== 'string' && !(body instanceof Uint8Array)) {
    return Promise.reject(new TypeError('fetch failed', {
      cause: new Error('a request through the proxy takes a string or byte body'),
    }));
  }
  if (body !== undefined) headers['content-length'] = String(Buffer.byteLength(body));
  const signal = init.signal ?? undefined;

  return new Promise<Response>((resolve, reject) => {
    const sockets: Array<{ destroy(): unknown }> = [];
    const track = <S extends { destroy(): unknown }>(socket: S): S => { sockets.push(socket); return socket; };
    let settled = false;
    const finish = (): boolean => {
      if (settled) return false;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      for (const socket of sockets) socket.destroy();
      return true;
    };
    const fail = (cause: unknown): void => {
      if (!finish()) return;
      reject(cause instanceof Error && cause.name === 'AbortError'
        ? cause
        : new TypeError('fetch failed', { cause }));
    };
    const onAbort = (): void => fail(abortError());
    if (signal?.aborted) { onAbort(); return; }
    signal?.addEventListener('abort', onAbort, { once: true });

    const onResponse = (res: http.IncomingMessage): void => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('error', fail);
      res.on('end', () => {
        try {
          const status = res.statusCode ?? 0;
          const responseHeaders = new Headers();
          for (const [name, value] of Object.entries(res.headers)) {
            for (const one of Array.isArray(value) ? value : value === undefined ? [] : [value]) {
              responseHeaders.append(name, one);
            }
          }
          const noBody = method === 'HEAD' || status === 204 || status === 205 || status === 304;
          const response = new Response(noBody ? null : Buffer.concat(chunks), {
            status,
            statusText: res.statusMessage ?? '',
            headers: responseHeaders,
          });
          if (finish()) resolve(response);
        } catch (err) {
          fail(err);
        }
      });
    };

    // Every request below names createConnection and no agent, so Node uses
    // that socket and no agent (or agent-level proxy) gets involved.
    const send = (options: http.RequestOptions, transport: typeof http | typeof https): void => {
      const req = transport.request({ ...options, method }, onResponse);
      req.on('error', fail);
      req.end(body);
    };

    if (target.protocol === 'http:') {
      // Absolute-form request: the proxy forwards it to the target.
      send({
        path: target.href,
        headers: { ...headers, host: target.host, ...proxyAuthorization(proxy) },
        createConnection: () => track(connectToProxy(proxy)),
      }, http);
      return;
    }

    const authority = `${target.hostname}:${portOf(target)}`;
    const tunnel = http.request({
      method: 'CONNECT',
      path: authority,
      headers: { host: authority, ...proxyAuthorization(proxy) },
      createConnection: () => track(connectToProxy(proxy)),
    });
    const refused = (res: http.IncomingMessage): void => {
      fail(new Error(`the proxy answered ${`${res.statusCode ?? 0} ${res.statusMessage ?? ''}`.trimEnd()} to CONNECT ${authority}`));
    };
    tunnel.on('error', fail);
    tunnel.on('response', refused);
    tunnel.on('connect', (res, socket) => {
      track(socket);
      const status = res.statusCode ?? 0;
      if (status < 200 || status > 299) {
        refused(res);
        return;
      }
      const host = bareHost(target);
      // `host` is the name the certificate is checked against. An IP address
      // is sent without SNI, and without `host` Node checks it as localhost.
      const secure = track(tls.connect({ socket, host, servername: tlsServerName(host), ALPNProtocols: ['http/1.1'] }));
      secure.on('error', fail);
      send({
        host,
        port: portOf(target),
        path: target.pathname + target.search,
        headers,
        createConnection: () => secure,
      }, https);
    });
    tunnel.end();
  });
}

/** One line that names the proxy and whether the request went through it. */
export function describeProxyRoute(route: ProxyRoute, target: string | URL): string {
  let host = String(target);
  try {
    const u = typeof target === 'string' ? new URL(target) : target;
    host = u.host;
  } catch { /* keep the raw target */ }
  const { proxy, routing } = route;
  if (routing === 'direct') {
    return `${proxy.variable} names the proxy ${proxy.url}, but the CLI (Node.js ${process.version}) ` +
      `sends requests only through an http:// or https:// proxy, so the request to ${host} went direct. ` +
      `Set ${proxy.variable} to an http:// or https:// proxy URL, or allow direct access to that host.`;
  }
  return `Requests to ${host} go through the proxy ${proxy.url} from ${proxy.variable}. ` +
    `Check that the proxy is reachable and allows connections to ${host}.`;
}
