import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { AimClient, API_KEY_HEADER } from '../../src/util/aim-client.js';

// The registration contract the AIM backend serves (agent-identity-management
// apps/backend/cmd/server/sdk_api_key_registration_contract_test.go): an agent API
// key registers through POST /api/v1/agents in X-API-Key, and the client sends the
// public half of a keypair it generated. /api/v1/public/agents/register reads only a
// JWT, and no backend route reads X-AIM-API-Key.

const mockFetch = vi.fn();

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function lastCall(): { url: string; init: RequestInit; headers: Record<string, string> } {
  const [url, init] = mockFetch.mock.calls.at(-1) as [string, RequestInit];
  return { url, init, headers: init.headers as Record<string, string> };
}

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const PUBLIC_KEY = Buffer.alloc(32, 7).toString('base64');

describe('AimClient.register', () => {
  it('posts POST /api/v1/agents with the key in X-API-Key and the public key in the body', async () => {
    mockFetch.mockResolvedValue(jsonResponse(201, {
      id: '6f1c2e8a-0000-4000-8000-000000000001',
      name: 'my-agent',
      displayName: 'my-agent',
      publicKey: PUBLIC_KEY,
      status: 'verified',
      trustScore: 0.5,
    }));
    const client = new AimClient('http://localhost:8080/');
    await client.register({ name: 'my-agent', publicKey: PUBLIC_KEY }, 'aim_live_example');

    const { url, init, headers } = lastCall();
    expect(url).toBe('http://localhost:8080/api/v1/agents');
    expect(init.method).toBe('POST');
    expect(API_KEY_HEADER).toBe('X-API-Key');
    expect(headers['X-API-Key']).toBe('aim_live_example');
    expect(Object.keys(headers).filter((h) => /aim-api-key/i.test(h))).toEqual([]);
    const body = JSON.parse(init.body as string);
    expect(body).toMatchObject({ name: 'my-agent', displayName: 'my-agent', publicKey: PUBLIC_KEY });
    expect(body).not.toHaveProperty('privateKey');
  });

  it('reads the agent id from the id field the route returns', async () => {
    mockFetch.mockResolvedValue(jsonResponse(201, {
      id: '6f1c2e8a-0000-4000-8000-000000000002',
      name: 'my-agent',
      displayName: 'my-agent',
      publicKey: PUBLIC_KEY,
      status: 'verified',
      trustScore: 0.5,
    }));
    const client = new AimClient('http://localhost:8080');
    const resp = await client.register({ name: 'my-agent', publicKey: PUBLIC_KEY }, 'aim_live_example');
    expect(resp.agentId).toBe('6f1c2e8a-0000-4000-8000-000000000002');
    expect(resp.publicKey).toBe(PUBLIC_KEY);
  });

  it('refuses to register without a public key, before any request', async () => {
    const client = new AimClient('http://localhost:8080');
    await expect(
      client.register({ name: 'my-agent', publicKey: '' }, 'aim_live_example'),
    ).rejects.toThrow(/public key/i);
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe('AimClient headers', () => {
  it('sends a configured API key as X-API-Key on authenticated calls', async () => {
    mockFetch.mockResolvedValue(jsonResponse(200, { agents: [], total: 0, page: 1, pageSize: 50 }));
    const client = new AimClient('http://localhost:8080', { apiKey: 'aim_live_example' });
    await client.listAgents('');
    expect(lastCall().headers['X-API-Key']).toBe('aim_live_example');
  });

  it('sends no API key when polling the device token, a route that reads none', async () => {
    mockFetch.mockResolvedValue(jsonResponse(200, {
      accessToken: 'a', refreshToken: 'r', tokenType: 'Bearer', expiresIn: 3600,
    }));
    const client = new AimClient('http://localhost:8080', { apiKey: 'aim_live_example' });
    await client.pollDeviceToken('device-code');
    const { url, headers } = lastCall();
    expect(url).toBe('http://localhost:8080/api/v1/oauth/device/token');
    expect(Object.keys(headers).filter((h) => /api-key/i.test(h))).toEqual([]);
  });

  it('names X-AIM-API-Key and the public registration route nowhere in the CLI source', () => {
    const root = join(__dirname, '..', '..', 'src');
    const hits: string[] = [];
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.(ts|js|mjs)$/.test(name)) {
          const src = readFileSync(p, 'utf-8');
          if (/X-AIM-API-Key|\/api\/v1\/public\/agents\/register/.test(src)) hits.push(p);
        }
      }
    };
    walk(root);
    expect(hits).toEqual([]);
  });
});
