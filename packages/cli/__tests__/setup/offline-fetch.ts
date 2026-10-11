// The suite runs offline. A test that reaches a code path which calls fetch
// without stubbing it (the advisory request in review() and init(), a
// Registry lookup) gets a refused request, as on a machine with no network,
// instead of contacting a live service and writing its answer into the
// cache under HOME. Loopback requests go through, for tests that run their
// own local server. A test that stubs fetch itself (vi.stubGlobal, or an
// assignment) replaces this for its own duration; vi.unstubAllGlobals()
// restores this stub, not the real fetch, because it is assigned here
// rather than stubbed.
//
// realFetch is the runtime's own fetch, for a test whose request names a
// host that never resolves and that only a local proxy answers: with
// Node.js's built-in proxy support the runtime hands it to the proxy after
// this stub has seen the URL (util/env-proxy.test.ts).

export const realFetch = globalThis.fetch;
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

function urlOf(input: Parameters<typeof fetch>[0]): URL {
  if (input instanceof URL) return input;
  return new URL(typeof input === 'string' ? input : input.url);
}

globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
  const url = urlOf(input);
  if (LOOPBACK.has(url.hostname)) return realFetch(input, init);
  throw new TypeError(`fetch failed: the test suite runs offline (${url.origin})`);
}) as typeof fetch;
