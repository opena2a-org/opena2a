/**
 * Child process for env-proxy.test.ts ("does not turn on a proxy for the rest
 * of the process").
 *
 * Stands in for a runtime without built-in proxy support, routes `target`
 * through the proxy in HTTP_PROXY, then sends a request for `target`/health
 * with the global fetch. Prints one JSON line: the routing and what fetch did.
 * It runs in its own process so that the proxy settings Node.js read when the
 * test runner started (NODE_USE_ENV_PROXY with HTTP_PROXY or HTTPS_PROXY)
 * cannot carry this fetch; the parent starts it without them.
 *
 * argv: <target>
 */
import { resetEnvProxy, routeThroughEnvProxy } from '../../../src/util/env-proxy.js';

async function main(): Promise<void> {
  const target = process.argv[2];
  resetEnvProxy({ builtInProxySupport: false });
  const routing = routeThroughEnvProxy(target)?.routing ?? null;
  let fetched: string;
  try {
    const res = await globalThis.fetch(`${target}/health`);
    fetched = `answered ${res.status}`;
  } catch {
    fetched = 'failed';
  }
  process.stdout.write(JSON.stringify({ routing, fetched }) + '\n');
}

void main();
