import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createServer, type Server, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';

// The identity server commands sign in with the key in OPENA2A_INTERNAL_API_KEY
// before --api-key and before what is stored, and send it in X-API-Key, the
// header the AIM server reads for authenticated calls. Credentials come from
// these mocks only: the test never reads or writes a real auth file, server
// config, keychain entry or identity.

const state = vi.hoisted(() => ({
  auth: null as null | { serverUrl: string; accessToken: string; expiresAt: string },
  serverConfig: null as null | {
    serverUrl: string;
    agentId: string;
    accessToken?: string;
    apiKey?: string;
    registeredAt: string;
  },
  dataDir: '',
}));

vi.mock('../../src/util/auth.js', () => ({
  loadAuth: () => state.auth,
  saveAuth: () => {
    throw new Error('saveAuth must not run in this test');
  },
  isAuthValid: (c: { expiresAt: string }) => Date.now() < new Date(c.expiresAt).getTime() - 60_000,
}));

vi.mock('../../src/util/aim-client.js', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../../src/util/aim-client.js')>();
  return {
    ...mod,
    loadServerConfig: () => state.serverConfig,
    saveServerConfig: () => {},
  };
});

vi.mock('@opena2a/aim-core', () => ({
  AIMCore: class {
    getDataDir(): string { return state.dataDir; }
    getIdentity() {
      return { agentId: 'local-agent', agentName: 'probe-agent', publicKey: 'not-a-real-public-key', createdAt: '2026-10-13T00:00:00.000Z' };
    }
    calculateTrust() { return { score: 40, grade: 'D', factors: { secretsManaged: 0 } }; }
    readAuditLog() { return []; }
    setTrustHints() {}
  },
}));

import { identity } from '../../src/commands/identity.js';

interface FakeAim {
  url: string;
  requests: Array<{ method: string; path: string; headers: IncomingHttpHeaders }>;
  close: () => Promise<void>;
}

const TAG = { id: 'tag-1', key: 'env', value: 'prod' };

/**
 * An AIM stub that records every request. Tag reads return one tag, so tag
 * add and tag remove reach their write; every other request gets one body
 * that each command accepts.
 */
async function startFakeAim(): Promise<FakeAim> {
  const requests: FakeAim['requests'] = [];
  const server: Server = createServer((req, res) => {
    requests.push({ method: req.method ?? '', path: req.url ?? '', headers: req.headers });
    res.setHeader('Content-Type', 'application/json');
    if (req.method === 'GET' && /\/tags$/.test(req.url ?? '')) {
      res.end(JSON.stringify({ tags: [TAG] }));
      return;
    }
    res.end(JSON.stringify({ agents: [], tags: [], policies: [], mcpServers: [], activities: [], total: 0, status: 'ok' }));
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
const ENV_KEY = 'FAKE-ENV-KEY-1234';

let aim: FakeAim;
let savedEnv: string | undefined;

beforeEach(async () => {
  aim = await startFakeAim();
  state.auth = null;
  state.serverConfig = null;
  state.dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-identity-env-key-'));
  fs.writeFileSync(path.join(state.dataDir, 'identity.json'), '{}');
  savedEnv = process.env.OPENA2A_INTERNAL_API_KEY;
  process.env.OPENA2A_INTERNAL_API_KEY = ENV_KEY;
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(async () => {
  vi.restoreAllMocks();
  if (savedEnv === undefined) delete process.env.OPENA2A_INTERNAL_API_KEY;
  else process.env.OPENA2A_INTERNAL_API_KEY = savedEnv;
  await aim.close();
  fs.rmSync(state.dataDir, { recursive: true, force: true });
});

/** The X-API-Key header of request `i`: the one header the AIM server reads an API key from. */
const apiKeyHeader = (i: number) => aim.requests[i].headers['x-api-key'];

/** Every request reached the server with the key in X-API-Key. */
function expectEveryRequestSends(key: string): void {
  expect(aim.requests.length).toBeGreaterThan(0);
  for (let i = 0; i < aim.requests.length; i++) {
    expect(apiKeyHeader(i), `${aim.requests[i].method} ${aim.requests[i].path}`).toBe(key);
  }
}

/** An agent connected to the stub, with no key and no token stored for it. */
function connectAgentWithoutCredentials(): void {
  state.serverConfig = { serverUrl: aim.url, agentId: 'agent-1', registeredAt: LATER };
}

const calls = () => aim.requests.map((r) => `${r.method} ${r.path}`);

describe('OPENA2A_INTERNAL_API_KEY signs in every identity server command, in X-API-Key', () => {
  it('identity list --server <url> authenticates with no --api-key and no stored credentials', async () => {
    expect(await identity({ subcommand: 'list', server: aim.url, json: true })).toBe(0);
    expect(calls()).toEqual(['GET /api/v1/agents']);
    expectEveryRequestSends(ENV_KEY);
  });

  it('identity policy --server <url>', async () => {
    expect(await identity({ subcommand: 'policy', server: aim.url, json: true })).toBe(0);
    expect(calls()).toEqual(['GET /api/v1/admin/security-policies']);
    expectEveryRequestSends(ENV_KEY);
  });

  it('identity tag list', async () => {
    connectAgentWithoutCredentials();
    expect(await identity({ subcommand: 'tag', args: ['list'], json: true })).toBe(0);
    expect(calls()).toEqual(['GET /api/v1/tags']);
    expectEveryRequestSends(ENV_KEY);
  });

  it('identity tag add', async () => {
    connectAgentWithoutCredentials();
    expect(await identity({ subcommand: 'tag', args: ['add', 'env=prod'], json: true })).toBe(0);
    expect(calls()).toEqual(['GET /api/v1/tags', 'POST /api/v1/agents/agent-1/tags']);
    expectEveryRequestSends(ENV_KEY);
  });

  it('identity tag remove', async () => {
    connectAgentWithoutCredentials();
    expect(await identity({ subcommand: 'tag', args: ['remove', 'env=prod'], json: true })).toBe(0);
    expect(calls()).toEqual(['GET /api/v1/agents/agent-1/tags', 'DELETE /api/v1/agents/agent-1/tags/tag-1']);
    expectEveryRequestSends(ENV_KEY);
  });

  it('identity mcp list', async () => {
    connectAgentWithoutCredentials();
    expect(await identity({ subcommand: 'mcp', args: ['list'], json: true })).toBe(0);
    expect(calls()).toEqual(['GET /api/v1/agents/agent-1/mcp-servers']);
    expectEveryRequestSends(ENV_KEY);
  });

  it('identity activity', async () => {
    connectAgentWithoutCredentials();
    expect(await identity({ subcommand: 'activity', json: true })).toBe(0);
    expect(calls()).toHaveLength(1);
    expect(calls()[0]).toMatch(/^GET \/api\/v1\/agents\/agent-1\/activity/);
    expectEveryRequestSends(ENV_KEY);
  });

  it('identity suspend', async () => {
    connectAgentWithoutCredentials();
    expect(await identity({ subcommand: 'suspend', json: true })).toBe(0);
    expect(calls()).toEqual(['POST /api/v1/agents/agent-1/suspend']);
    expectEveryRequestSends(ENV_KEY);
  });

  it('identity reactivate', async () => {
    connectAgentWithoutCredentials();
    expect(await identity({ subcommand: 'reactivate', json: true })).toBe(0);
    expect(calls()).toEqual(['POST /api/v1/agents/agent-1/reactivate']);
    expectEveryRequestSends(ENV_KEY);
  });

  it('identity revoke', async () => {
    connectAgentWithoutCredentials();
    expect(await identity({ subcommand: 'revoke', ci: true, json: true })).toBe(0);
    expect(calls()).toEqual(['POST /api/v1/agents/agent-1/revoke']);
    expectEveryRequestSends(ENV_KEY);
  });

  it('is read before --api-key and before the stored key', async () => {
    state.serverConfig = { serverUrl: aim.url, agentId: 'agent-1', apiKey: 'STORED-KEY', registeredAt: LATER };
    expect(await identity({ subcommand: 'list', server: aim.url, apiKey: 'TYPED-KEY', json: true })).toBe(0);
    expect(calls()).toEqual(['GET /api/v1/agents/agent-1']);
    expectEveryRequestSends(ENV_KEY);
  });

  it('a blank value is ignored and --api-key is used', async () => {
    process.env.OPENA2A_INTERNAL_API_KEY = '   ';
    connectAgentWithoutCredentials();
    expect(await identity({ subcommand: 'list', server: aim.url, apiKey: 'TYPED-KEY', json: true })).toBe(0);
    expect(calls()).toEqual(['GET /api/v1/agents/agent-1']);
    expectEveryRequestSends('TYPED-KEY');
  });
});

describe('with OPENA2A_INTERNAL_API_KEY unset', () => {
  beforeEach(() => {
    delete process.env.OPENA2A_INTERNAL_API_KEY;
  });

  it('identity list --api-key with no agent connected asks the server nothing', async () => {
    expect(await identity({ subcommand: 'list', server: aim.url, apiKey: 'TYPED-KEY', json: true })).toBe(0);
    expect(calls()).toEqual([]);
  });

  it('identity list with a stored key and no agent connected asks the server nothing', async () => {
    state.serverConfig = { serverUrl: aim.url, agentId: '', apiKey: 'STORED-KEY', registeredAt: LATER };
    expect(await identity({ subcommand: 'list', json: true })).toBe(0);
    expect(calls()).toEqual([]);
  });

  it('identity list --api-key fetches the connected agent with the typed key', async () => {
    connectAgentWithoutCredentials();
    expect(await identity({ subcommand: 'list', server: aim.url, apiKey: 'TYPED-KEY', json: true })).toBe(0);
    expect(calls()).toEqual(['GET /api/v1/agents/agent-1']);
    expectEveryRequestSends('TYPED-KEY');
  });

  it('identity policy --api-key sends the typed key as before, in X-AIM-API-Key', async () => {
    expect(await identity({ subcommand: 'policy', server: aim.url, apiKey: 'TYPED-KEY', json: true })).toBe(0);
    expect(calls()).toEqual(['GET /api/v1/admin/security-policies']);
    expect(aim.requests[0].headers['x-aim-api-key']).toBe('TYPED-KEY');
    expect(apiKeyHeader(0)).toBeUndefined();
  });

  it('identity tag list signs in with the login token, and no API key', async () => {
    state.auth = { serverUrl: aim.url, accessToken: 'LOGIN-TOKEN', expiresAt: LATER };
    expect(await identity({ subcommand: 'tag', args: ['list'], server: aim.url, json: true })).toBe(0);
    expect(calls()).toEqual(['GET /api/v1/tags']);
    expect(aim.requests[0].headers.authorization).toBe('Bearer LOGIN-TOKEN');
    expect(apiKeyHeader(0)).toBeUndefined();
  });

  it('identity tag list with no login is refused before any request', async () => {
    connectAgentWithoutCredentials();
    expect(await identity({ subcommand: 'tag', args: ['list'], json: true })).toBe(1);
    expect(calls()).toEqual([]);
  });
});
