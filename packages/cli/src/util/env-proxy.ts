/**
 * Proxy settings from the environment (HTTPS_PROXY, HTTP_PROXY, NO_PROXY)
 * for the CLI's own HTTP requests.
 *
 * Node's global fetch ignores these variables unless the runtime is told to
 * honour them. On a host whose only route out is a proxy, a request that
 * ignores them goes direct and fails with a generic network error. This module
 * turns on Node's built-in proxy support when the runtime offers it
 * (`http.setGlobalProxyFromEnv`), and otherwise reports that the request went
 * direct, so every failure line can name the proxy that applies.
 */

import * as http from 'node:http';

export interface EnvProxy {
  /** Proxy URL with any user name and password removed; safe to print. */
  url: string;
  /** The environment variable the proxy URL came from. */
  variable: string;
}

/**
 * How a request reaches the proxy:
 * - `cli`: the CLI turned on Node's built-in proxy support for this process.
 * - `runtime`: NODE_USE_ENV_PROXY=1 or --use-env-proxy asks Node to use it.
 * - `direct`: this runtime cannot send the request through the proxy.
 */
export type ProxyRouting = 'cli' | 'runtime' | 'direct';

export interface ProxyRoute {
  proxy: EnvProxy;
  routing: ProxyRouting;
}

type Env = Record<string, string | undefined>;

/** Remove user name and password from a proxy URL before it is printed. */
export function redactProxyUrl(raw: string): string {
  try {
    const u = new URL(raw);
    u.username = '';
    u.password = '';
    return u.toString().replace(/\/$/, '');
  } catch {
    // Not a parseable URL: drop anything that looks like userinfo.
    return raw.replace(/\/\/[^/@]*@/, '//');
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

function runtimeHonoursEnvProxy(env: Env): boolean {
  if (env.NODE_USE_ENV_PROXY === '1') return true;
  if (process.execArgv.includes('--use-env-proxy')) return true;
  return /(^|\s)--use-env-proxy(\s|$)/.test(env.NODE_OPTIONS ?? '');
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
  if (!/^https?:\/\//i.test(proxy.url)) return { proxy, routing: 'direct' };
  if (restoreGlobalProxy) return { proxy, routing: 'cli' };

  const setGlobal = (http as unknown as { setGlobalProxyFromEnv?: SetGlobalProxyFromEnv }).setGlobalProxyFromEnv;
  if (typeof setGlobal === 'function') {
    const noProxy = [env.no_proxy || env.NO_PROXY, LOOPBACK_NO_PROXY].filter(Boolean).join(',');
    try {
      restoreGlobalProxy = setGlobal({ ...env, no_proxy: noProxy, NO_PROXY: noProxy });
      return { proxy, routing: 'cli' };
    } catch {
      // Invalid proxy configuration: Node will not use it either.
      return { proxy, routing: 'direct' };
    }
  }
  return { proxy, routing: runtimeHonoursEnvProxy(env) ? 'runtime' : 'direct' };
}

/** Undo routeThroughEnvProxy for this process. Used by tests. */
export function resetEnvProxy(): void {
  restoreGlobalProxy?.();
  restoreGlobalProxy = null;
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
    return `${proxy.variable} names the proxy ${proxy.url}, but Node.js ${process.version} cannot send ` +
      `the CLI's requests through it, so the request to ${host} went direct. ` +
      'Run the CLI on a Node.js release with built-in proxy support (NODE_USE_ENV_PROXY=1), ' +
      'or allow direct access to that host.';
  }
  const how = routing === 'runtime' ? ' (Node.js built-in proxy support)' : '';
  return `Requests to ${host} go through the proxy ${proxy.url} from ${proxy.variable}${how}. ` +
    `Check that the proxy is reachable and allows connections to ${host}.`;
}
