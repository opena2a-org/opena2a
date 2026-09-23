import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const stdinKey = vi.hoisted(() => ({ value: '' }));
vi.mock('../../src/util/stdin-secret.js', () => ({ readSecretFromStdin: () => stdinKey.value }));

// `identity create --server` and `identity connect` register with an agent API key
// through POST /api/v1/agents with the public key of this machine's aim-core identity.
// aim-core keeps ONE identity per data directory, so a registration under a second name
// would bind the same key to two server agents; the CLI refuses it. The key comes from
// AIM_API_KEY or standard input (--api-key-stdin); a key on the command line is refused.

type IdentityFn = typeof import('../../src/commands/identity.js')['identity'];
type IdentityOptions = Parameters<IdentityFn>[0];

const SERVER = 'http://localhost:8080';
// The shape the backend mints: aim_live_ + URL-safe base64 of 32 bytes.
// TEST-ONLY synthetic key (32 bytes of 0x09), never a real credential: real keys never go in tests.
const API_KEY = `aim_live_${Buffer.alloc(32, 9).toString('base64url')}=`;

const mockFetch = vi.fn();
let home: string;
let savedHome: string | undefined;
let savedKey: string | undefined;
let registerStatus: number;
let registerBody: ((body: Record<string, unknown>) => unknown) | null;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function registrations(): Array<{ headers: Record<string, string>; body: Record<string, unknown> }> {
  return mockFetch.mock.calls
    .filter(([url, init]) => url === `${SERVER}/api/v1/agents` && (init as RequestInit).method === 'POST')
    .map(([, init]) => ({
      headers: (init as RequestInit).headers as Record<string, string>,
      body: JSON.parse((init as RequestInit).body as string) as Record<string, unknown>,
    }));
}

function localPublicKey(): string {
  return JSON.parse(readFileSync(join(home, '.opena2a', 'aim-core', 'identity.json'), 'utf-8')).publicKey;
}

function stderr(): string {
  return vi.mocked(process.stderr.write).mock.calls.map((c) => String(c[0])).join('');
}

// auth.ts and aim-client.ts resolve their paths under homedir() when the module loads,
// so each test imports the command afresh after pointing HOME at its scratch directory.
// Tests in one file run sequentially, and the import is awaited before the call.
async function loadIdentity(): Promise<IdentityFn> {
  vi.resetModules();
  return (await import('../../src/commands/identity.js')).identity;
}

beforeEach(() => {
  savedHome = process.env.HOME;
  savedKey = process.env.AIM_API_KEY;
  home = mkdtempSync(join(tmpdir(), 'opena2a-identity-register-'));
  process.env.HOME = home;
  delete process.env.AIM_API_KEY;
  registerStatus = 201;
  registerBody = null;
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
  mockFetch.mockImplementation(async (url: string, init: RequestInit) => {
    if (url === `${SERVER}/health`) return jsonResponse(200, { status: 'healthy' });
    if (url === `${SERVER}/api/v1/agents` && init.method === 'POST') {
      const body = JSON.parse(init.body as string) as Record<string, unknown>;
      if (registerStatus !== 201) return jsonResponse(registerStatus, { error: 'refused by the stub' });
      return jsonResponse(201, registerBody ? registerBody(body) : {
        id: `00000000-0000-4000-8000-${String(mockFetch.mock.calls.length).padStart(12, '0')}`,
        name: body.name, displayName: body.displayName, publicKey: body.publicKey,
        status: 'pending', trustScore: 0.5,
      });
    }
    return jsonResponse(404, { error: `unexpected request ${init.method} ${url}` });
  });
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  if (savedKey === undefined) delete process.env.AIM_API_KEY;
  else process.env.AIM_API_KEY = savedKey;
  rmSync(home, { recursive: true, force: true });
});

const serverConfig = () => join(home, '.opena2a', 'aim-core', 'identities', 'server.json');

describe('identity create --server with an agent API key', () => {
  it('reads the key from AIM_API_KEY and registers with the local identity public key', async () => {
    process.env.AIM_API_KEY = API_KEY;
    const identity = await loadIdentity();
    const opts: IdentityOptions = { subcommand: 'create', name: 'agent-one', server: 'localhost:8080', format: 'json' };
    expect(await identity(opts)).toBe(0);
    const regs = registrations();
    expect(regs).toHaveLength(1);
    expect(regs[0].headers['X-API-Key']).toBe(API_KEY);
    expect(regs[0].body.publicKey).toBe(localPublicKey());
    expect(stderr()).not.toMatch(/process list/);
  });

  it('refuses --api-key, names AIM_API_KEY and --api-key-stdin, and sends nothing', async () => {
    const identity = await loadIdentity();
    const opts: IdentityOptions = { subcommand: 'create', name: 'agent-one', server: 'localhost:8080', apiKey: API_KEY, format: 'json' };
    expect(await identity(opts)).toBe(1);
    expect(mockFetch).not.toHaveBeenCalled();
    expect(stderr()).toMatch(/process list/);
    expect(stderr()).toMatch(/AIM_API_KEY/);
    expect(stderr()).toMatch(/--api-key-stdin/);
    expect(stderr()).not.toContain(API_KEY);
  });

  it('reads the key from standard input with --api-key-stdin', async () => {
    stdinKey.value = API_KEY;
    const identity = await loadIdentity();
    const opts: IdentityOptions = { subcommand: 'create', name: 'agent-one', server: 'localhost:8080', apiKeyStdin: true, format: 'json' };
    expect(await identity(opts)).toBe(0);
    const regs = registrations();
    expect(regs).toHaveLength(1);
    expect(regs[0].headers['X-API-Key']).toBe(API_KEY);
  });

  it('refuses an empty standard input', async () => {
    stdinKey.value = '';
    const identity = await loadIdentity();
    expect(await identity({ subcommand: 'create', name: 'agent-one', server: 'localhost:8080', apiKeyStdin: true })).toBe(1);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('refuses a second name, which would put one key on two server agents', async () => {
    process.env.AIM_API_KEY = API_KEY;
    const identity = await loadIdentity();
    const base: IdentityOptions = { subcommand: 'create', server: 'localhost:8080', format: 'json' };
    expect(await identity({ ...base, name: 'agent-one' })).toBe(0);
    expect(await identity({ ...base, name: 'agent-two' })).toBe(1);
    expect(registrations()).toHaveLength(1);
    expect(stderr()).toMatch(/agent-one/);
    expect(stderr()).toMatch(/identity connect/);
  });

  it('stores nothing when the server refuses the key', async () => {
    process.env.AIM_API_KEY = API_KEY;
    registerStatus = 401;
    const identity = await loadIdentity();
    expect(await identity({ subcommand: 'create', name: 'agent-one', server: 'localhost:8080', format: 'json' })).toBe(1);
    expect(stderr()).toMatch(/Failed to register on server: Authentication/);
    expect(stderr()).not.toContain(API_KEY);
    expect(existsSync(serverConfig())).toBe(false);
  });

  it('stores nothing when the server answers without an agent id', async () => {
    process.env.AIM_API_KEY = API_KEY;
    registerBody = (body) => ({ name: body.name, status: 'pending' });
    const identity = await loadIdentity();
    expect(await identity({ subcommand: 'create', name: 'agent-one', server: 'localhost:8080', format: 'json' })).toBe(1);
    expect(stderr()).toMatch(/without an agent id/);
    expect(existsSync(serverConfig())).toBe(false);
  });
});

describe('identity connect with an agent API key', () => {
  it('registers the existing local identity with its public key', async () => {
    process.env.AIM_API_KEY = API_KEY;
    const identity = await loadIdentity();
    expect(await identity({ subcommand: 'create', name: 'local-agent', format: 'json' })).toBe(0);
    expect(await identity({ subcommand: 'connect', args: ['localhost:8080'], format: 'json' })).toBe(0);
    const regs = registrations();
    expect(regs).toHaveLength(1);
    expect(regs[0].headers['X-API-Key']).toBe(API_KEY);
    expect(regs[0].body).toMatchObject({ name: 'local-agent', publicKey: localPublicKey() });
    expect(existsSync(serverConfig())).toBe(true);
  });

  it('names AIM_API_KEY when no key is given', async () => {
    const identity = await loadIdentity();
    expect(await identity({ subcommand: 'create', name: 'local-agent', format: 'json' })).toBe(0);
    expect(await identity({ subcommand: 'connect', args: ['localhost:8080'], format: 'json' })).toBe(1);
    expect(registrations()).toHaveLength(0);
    expect(stderr()).toMatch(/AIM_API_KEY/);
  });
});
