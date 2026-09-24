import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { AimClient, AimServerError, API_KEY_HEADER, isAgentApiKey } from '../../src/util/aim-client.js';

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
// The shape api_key_service.go mints: aim_live_ + URL-safe base64 of 32 bytes (53 chars).
// TEST-ONLY synthetic key (32 bytes of 0x09), never a real credential: real keys never go in tests.
const API_KEY = `aim_live_${Buffer.alloc(32, 9).toString('base64url')}=`;

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
    await client.register({ name: 'my-agent', publicKey: PUBLIC_KEY }, API_KEY);

    const { url, init, headers } = lastCall();
    expect(url).toBe('http://localhost:8080/api/v1/agents');
    expect(init.method).toBe('POST');
    expect(API_KEY_HEADER).toBe('X-API-Key');
    expect(headers['X-API-Key']).toBe(API_KEY);
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
    const resp = await client.register({ name: 'my-agent', publicKey: PUBLIC_KEY }, API_KEY);
    expect(resp.agentId).toBe('6f1c2e8a-0000-4000-8000-000000000002');
    expect(resp.publicKey).toBe(PUBLIC_KEY);
  });

  it('refuses to register without a public key, before any request', async () => {
    const client = new AimClient('http://localhost:8080');
    await expect(
      client.register({ name: 'my-agent', publicKey: '' }, API_KEY),
    ).rejects.toThrow(/public key/i);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it.each([
    ['31 bytes', Buffer.alloc(31, 7).toString('base64')],
    ['33 bytes', Buffer.alloc(33, 7).toString('base64')],
    ['not base64', '!'.repeat(43) + '='],
    ['oversized', Buffer.alloc(4096, 7).toString('base64')],
  ])('refuses a public key that is not 32 bytes of base64 (%s), before any request', async (_label, key) => {
    const client = new AimClient('http://localhost:8080');
    await expect(client.register({ name: 'my-agent', publicKey: key }, API_KEY))
      .rejects.toThrow(/32-byte Ed25519/);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it.each([
    ['empty', ''],
    ['wrong prefix', API_KEY.replace('aim_live_', 'aim_test_')],
    ['truncated', API_KEY.slice(0, 30)],
    ['unpadded (the backend always pads)', API_KEY.slice(0, -1)],
    ['whitespace inside', API_KEY.slice(0, 20) + ' ' + API_KEY.slice(21)],
  ])('refuses an API key that is not an agent API key (%s), before any request', async (_label, key) => {
    const client = new AimClient('http://localhost:8080');
    await expect(client.register({ name: 'my-agent', publicKey: PUBLIC_KEY }, key))
      .rejects.toThrow(/not an AIM agent API key/);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('never echoes the key in the refusal', async () => {
    const client = new AimClient('http://localhost:8080');
    const bad = API_KEY.replace('aim_live_', 'aim_test_');
    const err = await client.register({ name: 'my-agent', publicKey: PUBLIC_KEY }, bad)
      .catch((e: unknown) => e);
    expect(String((err as Error).message)).not.toContain(bad.slice(9));
  });

  it('accepts the key shape the backend mints', () => {
    expect(isAgentApiKey(API_KEY)).toBe(true);
    expect(API_KEY).toHaveLength(53);
  });

  it.each([
    [401, { error: 'invalid API key' }],
    [403, { error: 'forbidden' }],
    [500, { error: 'internal' }],
  ])('surfaces a %s answer as AimServerError with the status', async (status, body) => {
    mockFetch.mockResolvedValue(jsonResponse(status, body));
    const client = new AimClient('http://localhost:8080');
    const err = await client.register({ name: 'my-agent', publicKey: PUBLIC_KEY }, API_KEY)
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AimServerError);
    expect((err as AimServerError).statusCode).toBe(status);
  });

  it('refuses a 201 answer that carries no agent id', async () => {
    mockFetch.mockResolvedValue(jsonResponse(201, { name: 'my-agent', status: 'pending' }));
    const client = new AimClient('http://localhost:8080');
    await expect(client.register({ name: 'my-agent', publicKey: PUBLIC_KEY }, API_KEY))
      .rejects.toThrow(/without an agent id/);
  });

  it('surfaces a connection failure as AimServerError without echoing the key', async () => {
    mockFetch.mockRejectedValue(new TypeError('fetch failed'));
    const client = new AimClient('http://localhost:8080');
    const err = await client.register({ name: 'my-agent', publicKey: PUBLIC_KEY }, API_KEY)
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AimServerError);
    expect((err as AimServerError).message).toMatch(/Cannot connect to AIM server/);
    expect((err as AimServerError).message).not.toContain(API_KEY);
  });

  it('refuses a 201 answer that is not JSON', async () => {
    mockFetch.mockResolvedValue(new Response('<html>proxy error</html>', { status: 201 }));
    const client = new AimClient('http://localhost:8080');
    await expect(client.register({ name: 'my-agent', publicKey: PUBLIC_KEY }, API_KEY))
      .rejects.toThrow(/Invalid JSON/);
  });
});

describe('AimClient headers', () => {
  it('sends a configured API key as X-API-Key on authenticated calls', async () => {
    mockFetch.mockResolvedValue(jsonResponse(200, { agents: [], total: 0, page: 1, pageSize: 50 }));
    const client = new AimClient('http://localhost:8080', { apiKey: API_KEY });
    await client.listAgents('');
    expect(lastCall().headers['X-API-Key']).toBe(API_KEY);
  });

  it('sends no API key when polling the device token, a route that reads none', async () => {
    mockFetch.mockResolvedValue(jsonResponse(200, {
      accessToken: 'a', refreshToken: 'r', tokenType: 'Bearer', expiresIn: 3600,
    }));
    const client = new AimClient('http://localhost:8080', { apiKey: API_KEY });
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
