import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// `identity create --server --api-key` and `identity connect --api-key` register
// through POST /api/v1/agents with the public key of this machine's aim-core
// identity. aim-core keeps ONE identity per data directory, so a registration under
// a second name would bind the same key to two server agents; the CLI refuses it.

const mockFetch = vi.fn();
let home: string;
let savedHome: string | undefined;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function registrations(): Array<{ url: string; headers: Record<string, string>; body: any }> {
  return mockFetch.mock.calls
    .filter(([url, init]) => String(url).endsWith('/api/v1/agents') && (init as RequestInit).method === 'POST')
    .map(([url, init]) => ({
      url: String(url),
      headers: (init as RequestInit).headers as Record<string, string>,
      body: JSON.parse((init as RequestInit).body as string),
    }));
}

function localPublicKey(): string {
  return JSON.parse(readFileSync(join(home, '.opena2a', 'aim-core', 'identity.json'), 'utf-8')).publicKey;
}

async function loadIdentity() {
  vi.resetModules();
  return (await import('../../src/commands/identity.js')).identity;
}

beforeEach(() => {
  savedHome = process.env.HOME;
  home = mkdtempSync(join(tmpdir(), 'opena2a-identity-register-'));
  process.env.HOME = home;
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
  mockFetch.mockImplementation(async (url: string, init: RequestInit) => {
    if (String(url).endsWith('/health')) return jsonResponse(200, { status: 'healthy' });
    if (String(url).endsWith('/api/v1/agents') && init.method === 'POST') {
      const body = JSON.parse(init.body as string);
      return jsonResponse(201, {
        id: `00000000-0000-4000-8000-${String(mockFetch.mock.calls.length).padStart(12, '0')}`,
        name: body.name, displayName: body.displayName, publicKey: body.publicKey,
        status: 'pending', trustScore: 0.5,
      });
    }
    return jsonResponse(404, { error: 'not found' });
  });
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  rmSync(home, { recursive: true, force: true });
});

describe('identity create --server --api-key', () => {
  it('registers through POST /api/v1/agents in X-API-Key with the local identity public key', async () => {
    const identity = await loadIdentity();
    const rc = await identity({
      subcommand: 'create', name: 'agent-one', server: 'localhost:8080', apiKey: 'aim_live_example', format: 'json',
    } as any);
    expect(rc).toBe(0);
    const regs = registrations();
    expect(regs).toHaveLength(1);
    expect(regs[0].url).toBe('http://localhost:8080/api/v1/agents');
    expect(regs[0].headers['X-API-Key']).toBe('aim_live_example');
    expect(regs[0].body.publicKey).toBe(localPublicKey());
  });

  it('refuses a second name, which would put one key on two server agents', async () => {
    const identity = await loadIdentity();
    const base = { subcommand: 'create', server: 'localhost:8080', apiKey: 'aim_live_example', format: 'json' };
    expect(await identity({ ...base, name: 'agent-one' } as any)).toBe(0);
    expect(await identity({ ...base, name: 'agent-two' } as any)).toBe(1);
    expect(registrations()).toHaveLength(1);
    const stderr = (process.stderr.write as any).mock.calls.map((c: unknown[]) => String(c[0])).join('');
    expect(stderr).toMatch(/agent-one/);
    expect(stderr).toMatch(/identity connect/);
  });
});

describe('identity connect --api-key', () => {
  it('registers the existing local identity with its public key', async () => {
    const identity = await loadIdentity();
    expect(await identity({ subcommand: 'create', name: 'local-agent', format: 'json' } as any)).toBe(0);
    const rc = await identity({
      subcommand: 'connect', args: ['localhost:8080'], apiKey: 'aim_live_example', format: 'json',
    } as any);
    expect(rc).toBe(0);
    const regs = registrations();
    expect(regs).toHaveLength(1);
    expect(regs[0].headers['X-API-Key']).toBe('aim_live_example');
    expect(regs[0].body).toMatchObject({ name: 'local-agent', publicKey: localPublicKey() });
  });
});
