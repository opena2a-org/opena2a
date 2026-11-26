import { describe, it, expect, vi, beforeEach, afterEach, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

// A key in OPENA2A_INTERNAL_API_KEY stays in the environment: identity create
// and identity connect save the agent connection with the real
// saveServerConfig, into a temporary home folder, and the key is in no file
// there. saveAuth (the login store and the keychain) must not run at all.

const state = vi.hoisted(() => ({ home: '', dataDir: '', saveAuthCalls: 0 }));

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => state.home };
});

vi.mock('../../src/util/auth.js', () => ({
  loadAuth: () => null,
  saveAuth: () => {
    state.saveAuthCalls++;
    throw new Error('saveAuth must not run in this test');
  },
  isAuthValid: () => false,
}));

vi.mock('@opena2a/aim-core', () => ({
  AIMCore: class {
    getDataDir(): string { return state.dataDir; }
    getIdentity() {
      return { agentId: 'local-agent', agentName: 'probe-agent', publicKey: 'not-a-real-public-key', createdAt: '2026-10-13T00:00:00.000Z' };
    }
    logEvent() {}
  },
}));

const realOs = await vi.importActual<typeof import('node:os')>('node:os');
state.home = fs.mkdtempSync(path.join(realOs.tmpdir(), 'opena2a-env-key-home-'));
state.dataDir = path.join(state.home, 'identity-data');

// Imported after the home folder is set: the stored config's path is fixed at import.
const { identity } = await import('../../src/commands/identity.js');

const ENV_KEY = 'FAKE-ENV-KEY-5678';
const TYPED_KEY = 'FAKE-TYPED-KEY-9012';
const configFile = () => path.join(state.home, '.opena2a', 'aim-core', 'identities', 'server.json');

let server: Server;
let url = '';
let savedEnv: string | undefined;

/** Every file under the temporary home folder whose content holds `needle`. */
function filesHolding(needle: string): string[] {
  const hits: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (fs.readFileSync(p, 'utf-8').includes(needle)) hits.push(p);
    }
  };
  walk(state.home);
  return hits;
}

beforeEach(async () => {
  server = createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ status: 'ok', agentId: 'agent-1', name: 'probe-agent' }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  fs.rmSync(path.join(state.home, '.opena2a'), { recursive: true, force: true });
  fs.mkdirSync(state.dataDir, { recursive: true });
  fs.writeFileSync(path.join(state.dataDir, 'identity.json'), '{}');
  state.saveAuthCalls = 0;
  savedEnv = process.env.OPENA2A_INTERNAL_API_KEY;
  process.env.OPENA2A_INTERNAL_API_KEY = ENV_KEY;
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(async () => {
  vi.restoreAllMocks();
  if (savedEnv === undefined) delete process.env.OPENA2A_INTERNAL_API_KEY;
  else process.env.OPENA2A_INTERNAL_API_KEY = savedEnv;
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

afterAll(() => {
  fs.rmSync(state.home, { recursive: true, force: true });
});

describe('a key from OPENA2A_INTERNAL_API_KEY is never stored', () => {
  it('identity create --server saves the connection without the key', async () => {
    expect(await identity({ subcommand: 'create', name: 'probe-agent', server: url, json: true })).toBe(0);
    const saved = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(saved.agentId).toBe('agent-1');
    expect(saved.apiKey).toBeUndefined();
    expect(filesHolding(ENV_KEY)).toEqual([]);
    expect(state.saveAuthCalls).toBe(0);
  });

  it('identity connect saves the connection without the key', async () => {
    expect(await identity({ subcommand: 'connect', args: [url], json: true })).toBe(0);
    const saved = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(saved.agentId).toBe('agent-1');
    expect(saved.apiKey).toBeUndefined();
    expect(filesHolding(ENV_KEY)).toEqual([]);
    expect(state.saveAuthCalls).toBe(0);
  });

  it('identity create --api-key, with the variable set, stores neither key', async () => {
    expect(await identity({ subcommand: 'create', name: 'probe-agent', server: url, apiKey: TYPED_KEY, json: true })).toBe(0);
    expect(filesHolding(ENV_KEY)).toEqual([]);
    expect(JSON.parse(fs.readFileSync(configFile(), 'utf-8')).apiKey).toBeUndefined();
  });
});

describe('with OPENA2A_INTERNAL_API_KEY unset, a typed key is stored as before', () => {
  beforeEach(() => {
    delete process.env.OPENA2A_INTERNAL_API_KEY;
  });

  it('identity create --server --api-key', async () => {
    expect(await identity({ subcommand: 'create', name: 'probe-agent', server: url, apiKey: TYPED_KEY, json: true })).toBe(0);
    expect(JSON.parse(fs.readFileSync(configFile(), 'utf-8')).apiKey).toBe(TYPED_KEY);
  });

  it('identity connect --api-key', async () => {
    expect(await identity({ subcommand: 'connect', args: [url], apiKey: TYPED_KEY, json: true })).toBe(0);
    expect(JSON.parse(fs.readFileSync(configFile(), 'utf-8')).apiKey).toBe(TYPED_KEY);
  });
});
