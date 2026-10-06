import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createServer, type Server, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';

// Credentials come from these mocks only: the test never reads or writes a
// real auth file, server config or keychain entry.
const authState = vi.hoisted(() => ({
  auth: null as null | { serverUrl: string; accessToken: string; expiresAt: string },
  serverConfig: null as null | { serverUrl: string; agentId: string; accessToken?: string; registeredAt: string },
}));

vi.mock('../../src/util/auth.js', () => ({
  loadAuth: () => authState.auth,
  saveAuth: () => {
    throw new Error('saveAuth must not run in this test');
  },
  isAuthValid: (c: { expiresAt: string }) => Date.now() < new Date(c.expiresAt).getTime() - 60_000,
}));

vi.mock('../../src/util/aim-client.js', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../../src/util/aim-client.js')>();
  return {
    ...mod,
    loadServerConfig: () => authState.serverConfig,
    saveServerConfig: () => {
      throw new Error('saveServerConfig must not run in this test');
    },
  };
});

import { identity } from '../../src/commands/identity.js';

interface FakeAim {
  url: string;
  requests: Array<{ path: string; headers: IncomingHttpHeaders }>;
  close: () => Promise<void>;
}

async function startFakeAim(policyName: string): Promise<FakeAim> {
  const requests: FakeAim['requests'] = [];
  const server: Server = createServer((req, res) => {
    requests.push({ path: req.url ?? '', headers: req.headers });
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      policies: [{ id: `${policyName}-id`, name: policyName, type: 'capability', enabled: true, rules: [] }],
    }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const LATER = new Date(Date.now() + 3_600_000).toISOString();

describe('identity policy --server <url>', () => {
  let loggedIn: FakeAim;
  let named: FakeAim;
  let stdout: string;
  let stderr: string;

  beforeEach(async () => {
    loggedIn = await startFakeAim('logged-in-server-policy');
    named = await startFakeAim('named-server-policy');
    authState.auth = { serverUrl: loggedIn.url, accessToken: 'token-for-logged-in-server', expiresAt: LATER };
    authState.serverConfig = null;
    stdout = '';
    stderr = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stdout += String(chunk);
      return true;
    });
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderr += String(chunk);
      return true;
    });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await loggedIn.close();
    await named.close();
  });

  it('queries the named server with --api-key, not the logged-in server', async () => {
    const code = await identity({ subcommand: 'policy', server: named.url, apiKey: 'named-server-key' });

    expect(code).toBe(0);
    expect(loggedIn.requests).toHaveLength(0);
    expect(named.requests).toHaveLength(1);
    expect(named.requests[0].path).toBe('/api/v1/admin/security-policies');
    expect(named.requests[0].headers['x-aim-api-key']).toBe('named-server-key');
    expect(named.requests[0].headers.authorization).toBeUndefined();
    expect(stdout).toContain(`Server Policies (${named.url})`);
    expect(stdout).toContain('named-server-policy');
    expect(stdout).not.toContain('logged-in-server-policy');
  });

  it('never sends the token stored for another server, and says how to log in to the named one', async () => {
    const code = await identity({ subcommand: 'policy', server: named.url });

    expect(code).toBe(1);
    expect(loggedIn.requests).toHaveLength(0);
    expect(named.requests).toHaveLength(0);
    expect(stdout).toBe('');
    expect(stderr).toContain(`Not logged in to ${named.url}.`);
    expect(stderr).toContain(`opena2a login --server ${named.url}`);
    expect(stderr).toContain(`opena2a identity policy --server ${named.url} --api-key <key>`);
  });

  it('uses the login token when --server names the logged-in server', async () => {
    const code = await identity({ subcommand: 'policy', server: loggedIn.url, json: true });

    expect(code).toBe(0);
    expect(named.requests).toHaveLength(0);
    expect(loggedIn.requests).toHaveLength(1);
    expect(loggedIn.requests[0].headers.authorization).toBe('Bearer token-for-logged-in-server');
    expect(JSON.parse(stdout).policies[0].name).toBe('logged-in-server-policy');
  });

  it('uses the login token for the named server when the agent is connected elsewhere', async () => {
    authState.serverConfig = {
      serverUrl: loggedIn.url,
      agentId: 'agent-1',
      accessToken: 'agent-token-for-other-server',
      registeredAt: LATER,
    };
    authState.auth = { serverUrl: named.url, accessToken: 'token-for-named-server', expiresAt: LATER };

    const code = await identity({ subcommand: 'policy', server: `${named.url}/` });

    expect(code).toBe(0);
    expect(loggedIn.requests).toHaveLength(0);
    expect(named.requests).toHaveLength(1);
    expect(named.requests[0].headers.authorization).toBe('Bearer token-for-named-server');
  });
});
