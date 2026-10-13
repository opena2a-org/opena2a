import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createServer, type Server, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';

// `identity list`, `show`, `trust` and `audit` read the agent from the AIM
// server with the credentials stored for it. Credentials come from these
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

/** An AIM stub that answers the agent, agent-list and audit-log reads. */
async function startFakeAim(): Promise<FakeAim> {
  const requests: FakeAim['requests'] = [];
  const server: Server = createServer((req, res) => {
    const reqPath = req.url ?? '';
    requests.push({ method: req.method ?? '', path: reqPath, headers: req.headers });
    res.setHeader('Content-Type', 'application/json');
    const agent = { id: 'agent-1', name: 'probe-agent', status: 'active', trustScore: 50 };
    if (reqPath.startsWith('/api/v1/agents/agent-1/audit-logs')) {
      res.end(JSON.stringify({ logs: [], total: 0 }));
    } else if (reqPath === '/api/v1/agents/agent-1') {
      res.end(JSON.stringify(agent));
    } else if (reqPath.startsWith('/api/v1/agents')) {
      res.end(JSON.stringify({ agents: [agent], total: 1 }));
    } else if (reqPath === '/api/v1/public/login') {
      // The AIM login handler takes an email address and a password.
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Email and password are required' }));
    } else {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'not found' }));
    }
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

let issuer: FakeAim;
let other: FakeAim;
let stdout: string;

beforeEach(async () => {
  issuer = await startFakeAim();
  other = await startFakeAim();
  state.auth = null;
  state.serverConfig = null;
  state.dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-identity-credentials-'));
  fs.writeFileSync(path.join(state.dataDir, 'identity.json'), '{}');
  stdout = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
    stdout += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(async () => {
  vi.restoreAllMocks();
  await issuer.close();
  await other.close();
  fs.rmSync(state.dataDir, { recursive: true, force: true });
});

describe('a stored token goes only to the server it was stored for', () => {
  it('identity list --server <url> does not send the login token of another server', async () => {
    state.auth = { serverUrl: issuer.url, accessToken: 'token-issued-by-issuer', expiresAt: LATER };

    const code = await identity({ subcommand: 'list', server: other.url, json: true });

    expect(code).toBe(0);
    expect(other.requests).toEqual([]);
    expect(issuer.requests).toEqual([]);
    expect(JSON.parse(stdout).server).toBeUndefined();
  });

  it('identity show --server <url> does not send the token of an agent connected to another server', async () => {
    state.serverConfig = { serverUrl: issuer.url, agentId: 'agent-1', accessToken: 'token-issued-by-issuer', registeredAt: LATER };

    const code = await identity({ subcommand: 'show', server: other.url, json: true });

    expect(code).toBe(0);
    expect(other.requests).toEqual([]);
    expect(issuer.requests).toEqual([]);
  });

  it('identity trust --server <url> does not send the token of an agent connected to another server', async () => {
    state.serverConfig = { serverUrl: issuer.url, agentId: 'agent-1', accessToken: 'token-issued-by-issuer', registeredAt: LATER };

    const code = await identity({ subcommand: 'trust', server: other.url, json: true, dir: state.dataDir });

    expect(code).toBe(0);
    expect(other.requests).toEqual([]);
    expect(issuer.requests).toEqual([]);
    expect(JSON.parse(stdout).server).toBeUndefined();
  });

  it('identity list sends the login token to the server that issued it', async () => {
    state.auth = { serverUrl: issuer.url, accessToken: 'token-issued-by-issuer', expiresAt: LATER };

    const code = await identity({ subcommand: 'list', server: issuer.url, json: true });

    expect(code).toBe(0);
    expect(other.requests).toEqual([]);
    expect(issuer.requests.map((r) => `${r.method} ${r.path}`)).toEqual(['GET /api/v1/agents']);
    expect(issuer.requests[0].headers.authorization).toBe('Bearer token-issued-by-issuer');
    expect(JSON.parse(stdout).server.agents).toHaveLength(1);
  });

  it('identity show and trust send the agent connection token to its own server', async () => {
    state.serverConfig = { serverUrl: issuer.url, agentId: 'agent-1', accessToken: 'token-issued-by-issuer', registeredAt: LATER };

    expect(await identity({ subcommand: 'show', json: true })).toBe(0);
    expect(JSON.parse(stdout).server).toMatchObject({ id: 'agent-1', trustScore: 50 });
    stdout = '';
    expect(await identity({ subcommand: 'trust', json: true, dir: state.dataDir })).toBe(0);
    expect(JSON.parse(stdout).server).toMatchObject({ trustScore: 50 });

    expect(other.requests).toEqual([]);
    expect(issuer.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      'GET /api/v1/agents/agent-1',
      'GET /api/v1/agents/agent-1',
    ]);
    for (const r of issuer.requests) expect(r.headers.authorization).toBe('Bearer token-issued-by-issuer');
  });
});

describe('the stored API key reads the agent in X-API-Key, without the login endpoint', () => {
  beforeEach(() => {
    state.serverConfig = { serverUrl: issuer.url, agentId: 'agent-1', apiKey: 'FAKE-AIM-KEY-1234', registeredAt: LATER };
  });

  it('identity list', async () => {
    const code = await identity({ subcommand: 'list', json: true });

    expect(code).toBe(0);
    expect(issuer.requests.map((r) => `${r.method} ${r.path}`)).toEqual(['GET /api/v1/agents/agent-1']);
    expect(issuer.requests[0].headers['x-api-key']).toBe('FAKE-AIM-KEY-1234');
    expect(issuer.requests[0].headers.authorization).toBeUndefined();
    expect(JSON.parse(stdout).server).toMatchObject({ id: 'agent-1', trustScore: 50 });
  });

  it('identity trust', async () => {
    const code = await identity({ subcommand: 'trust', json: true, dir: state.dataDir });

    expect(code).toBe(0);
    expect(issuer.requests.map((r) => `${r.method} ${r.path}`)).toEqual(['GET /api/v1/agents/agent-1']);
    expect(issuer.requests[0].headers['x-api-key']).toBe('FAKE-AIM-KEY-1234');
    expect(JSON.parse(stdout).server).toMatchObject({ trustScore: 50 });
  });

  it('identity audit', async () => {
    const code = await identity({ subcommand: 'audit', json: true });

    expect(code).toBe(0);
    expect(issuer.requests.map((r) => `${r.method} ${r.path}`)).toEqual(['GET /api/v1/agents/agent-1/audit-logs?pageSize=10']);
    expect(issuer.requests[0].headers['x-api-key']).toBe('FAKE-AIM-KEY-1234');
    expect(JSON.parse(stdout)).toMatchObject({ source: 'server', total: 0, auditLogs: [] });
  });

  it('identity list --server <url> does not send the key stored for another server', async () => {
    const code = await identity({ subcommand: 'list', server: other.url, json: true });

    expect(code).toBe(0);
    expect(other.requests).toEqual([]);
    expect(issuer.requests).toEqual([]);
  });

  it('identity list --server <url> with a login for that server carries no key stored for another server', async () => {
    state.auth = { serverUrl: other.url, accessToken: 'token-issued-by-other', expiresAt: LATER };

    const code = await identity({ subcommand: 'list', server: other.url, json: true });

    expect(code).toBe(0);
    expect(issuer.requests).toEqual([]);
    expect(other.requests.map((r) => `${r.method} ${r.path}`)).toEqual(['GET /api/v1/agents/agent-1']);
    expect(other.requests[0].headers.authorization).toBe('Bearer token-issued-by-other');
    expect(other.requests[0].headers['x-api-key']).toBeUndefined();
    expect(other.requests[0].headers['x-aim-api-key']).toBeUndefined();
  });
});
