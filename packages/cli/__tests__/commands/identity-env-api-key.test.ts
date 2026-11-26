import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createServer, type Server, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';

// The identity server commands sign in with the key in OPENA2A_INTERNAL_API_KEY
// before --api-key and before what is stored. Credentials come from these
// mocks only: the test never reads or writes a real auth file, server config,
// keychain entry or identity.

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

/** An AIM stub that answers every read with an empty list and records the request. */
async function startFakeAim(): Promise<FakeAim> {
  const requests: FakeAim['requests'] = [];
  const server: Server = createServer((req, res) => {
    requests.push({ method: req.method ?? '', path: req.url ?? '', headers: req.headers });
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ agents: [], tags: [], policies: [], total: 0 }));
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

// The client sends a key in X-AIM-API-Key, and a per-call key also in X-API-Key.
const keyOf = (i: number) => aim.requests[i].headers['x-api-key'] ?? aim.requests[i].headers['x-aim-api-key'];

describe('OPENA2A_INTERNAL_API_KEY signs in every identity server command', () => {
  it('identity list --server <url> authenticates with no --api-key and no stored credentials', async () => {
    expect(await identity({ subcommand: 'list', server: aim.url, json: true })).toBe(0);
    expect(aim.requests.map((r) => `${r.method} ${r.path}`)).toEqual(['GET /api/v1/agents']);
    expect(keyOf(0)).toBe(ENV_KEY);
  });

  it('identity policy --server <url> authenticates', async () => {
    expect(await identity({ subcommand: 'policy', server: aim.url, json: true })).toBe(0);
    expect(aim.requests.length).toBeGreaterThan(0);
    expect(keyOf(0)).toBe(ENV_KEY);
  });

  it('identity tag list authenticates without a login', async () => {
    expect(await identity({ subcommand: 'tag', args: ['list'], server: aim.url, json: true })).toBe(0);
    expect(aim.requests.length).toBe(1);
    expect(keyOf(0)).toBe(ENV_KEY);
  });

  it('is read before --api-key and before the stored key', async () => {
    state.serverConfig = { serverUrl: aim.url, agentId: 'agent-1', apiKey: 'STORED-KEY', registeredAt: LATER };
    expect(await identity({ subcommand: 'list', server: aim.url, apiKey: 'TYPED-KEY', json: true })).toBe(0);
    expect(aim.requests.length).toBeGreaterThan(0);
    for (let i = 0; i < aim.requests.length; i++) expect(keyOf(i)).toBe(ENV_KEY);
  });

  it('a blank value is ignored and --api-key is used', async () => {
    process.env.OPENA2A_INTERNAL_API_KEY = '   ';
    expect(await identity({ subcommand: 'list', server: aim.url, apiKey: 'TYPED-KEY', json: true })).toBe(0);
    expect(keyOf(0)).toBe('TYPED-KEY');
  });
});
