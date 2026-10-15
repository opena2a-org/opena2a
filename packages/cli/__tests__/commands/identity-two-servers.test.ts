import { describe, it, expect, vi, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import { createServer, type Server, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';

// Every identity subcommand that sends a request to an AIM server, run
// against two local servers, A and B, with --server A, --server B and no
// --server. The login and the agent connection are written to a temporary
// home directory in the shape `opena2a login` and `identity connect` write
// them, and the CLI reads them with its own loaders.
//
// Each request a server receives may carry only the token, API key and agent
// ID stored for that server's origin. A server with nothing stored receives
// nothing stored, no sign-in header carries a value that was not stored for
// that server, no name or ID the CLI sends is a placeholder, and a command
// given --server X sends nothing to the other server. A key typed with
// --api-key goes only to the server it was typed for.

vi.mock('@opena2a/aim-core', () => ({
  AIMCore: class {
    getDataDir(): string {
      return state.dataDir;
    }
    getIdentity() {
      return { agentId: 'local-agent', agentName: 'probe-agent', publicKey: 'not-a-real-public-key', createdAt: '2026-10-15T00:00:00.000Z' };
    }
    calculateTrust() {
      return { score: 40, grade: 'D', factors: { secretsManaged: 0 } };
    }
    readAuditLog() {
      return [];
    }
    loadPolicy() {
      return { version: '1', defaultAction: 'allow', rules: [] };
    }
    logEvent(event: Record<string, unknown>) {
      return { ...event, timestamp: '2026-10-15T00:00:00.000Z' };
    }
    setTrustHints() {}
  },
}));

// The trust score contribution goes to the Registry, not to an AIM server.
vi.mock('../../src/util/report-submission.js', () => ({
  recordScanAndMaybePrompt: async () => {},
  isContributeEnabled: async () => false,
  getRegistryUrl: async () => null,
  submitScanReport: async () => {},
}));

const state = vi.hoisted(() => ({ dataDir: '' }));

type IdentityFn = typeof import('../../src/commands/identity.js').identity;
type IdentityOptions = Parameters<IdentityFn>[0];
type Label = 'A' | 'B';

interface CapturedRequest {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: string;
}

interface CaptureServer {
  url: string;
  requests: CapturedRequest[];
  close: () => Promise<void>;
}

/** One answer for every AIM route the identity subcommands call. */
const ANSWER = JSON.stringify({
  status: 'active',
  id: 'object-from-server',
  agentId: 'agent-from-server',
  name: 'probe-agent',
  trustScore: 50,
  agents: [],
  total: 0,
  logs: [],
  tags: [{ id: 'tag-1', key: 'environment', value: 'production' }],
  mcpServers: [],
  policies: [],
  events: [],
});

async function startCaptureServer(): Promise<CaptureServer> {
  const requests: CapturedRequest[] = [];
  const server: Server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += String(chunk); });
    req.on('end', () => {
      requests.push({ method: req.method ?? '', path: req.url ?? '', headers: req.headers, body });
      res.setHeader('Content-Type', 'application/json');
      res.end(ANSWER);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** A value unique to this run, assembled from parts. */
function made(...parts: string[]): string {
  return [...parts, randomBytes(6).toString('hex')].join('-');
}

interface StoredFor {
  loginAccess: string;
  loginRefresh: string;
  connectionAccess: string;
  apiKey: string;
  agentId: string;
}

function valuesFor(label: Label): StoredFor {
  const l = label.toLowerCase();
  return {
    loginAccess: made('login', 'access', l),
    loginRefresh: made('login', 'refresh', l),
    connectionAccess: made('connection', 'access', l),
    apiKey: made('aim', 'key', l),
    agentId: made('agent', l),
  };
}

interface Setup {
  name: string;
  login: Label;
  connection: Label;
  /** Whether the agent connection holds a token too, as `opena2a setup` writes it. */
  connectionToken: boolean;
}

const SETUPS: Setup[] = [
  { name: 'login, API key and agent ID stored for A only', login: 'A', connection: 'A', connectionToken: false },
  { name: 'login stored for A; API key, token and agent ID stored for B', login: 'A', connection: 'B', connectionToken: true },
  { name: 'login stored for B; API key, token and agent ID stored for A', login: 'B', connection: 'A', connectionToken: true },
];

interface Command {
  label: string;
  /** Whether identity takes --server for it; connect takes its server as a positional URL. */
  takesServer: boolean;
  options: (serverUrl: string | undefined) => IdentityOptions;
}

interface Column {
  server?: Label;
  /** Whether the command is run with --api-key as well. */
  typed: boolean;
}

let projectDir = '';
let explicitKey = '';

const COMMANDS: Command[] = [
  { label: 'list', takesServer: true, options: (s) => ({ subcommand: 'list', server: s, json: true }) },
  { label: 'show', takesServer: true, options: (s) => ({ subcommand: 'show', server: s, json: true }) },
  { label: 'create probe-agent', takesServer: true, options: (s) => ({ subcommand: 'create', args: ['probe-agent'], server: s, json: true }) },
  { label: 'trust', takesServer: true, options: (s) => ({ subcommand: 'trust', server: s, dir: projectDir, json: true }) },
  { label: 'audit', takesServer: false, options: (s) => ({ subcommand: 'audit', server: s, json: true }) },
  {
    label: 'connect <url> --api-key <key>',
    takesServer: true,
    options: (s) => ({ subcommand: 'connect', args: s ? [s] : [], apiKey: explicitKey, json: true }),
  },
  { label: 'policy', takesServer: true, options: (s) => ({ subcommand: 'policy', server: s, json: true }) },
  { label: 'tag list', takesServer: true, options: (s) => ({ subcommand: 'tag', args: ['list'], server: s, json: true }) },
  { label: 'tag add', takesServer: true, options: (s) => ({ subcommand: 'tag', args: ['add', 'environment=production'], server: s, json: true }) },
  { label: 'tag remove', takesServer: true, options: (s) => ({ subcommand: 'tag', args: ['remove', 'environment=production'], server: s, json: true }) },
  { label: 'mcp list', takesServer: true, options: (s) => ({ subcommand: 'mcp', args: ['list'], server: s, json: true }) },
  { label: 'mcp add', takesServer: true, options: (s) => ({ subcommand: 'mcp', args: ['add', 'mcp-1'], server: s, json: true }) },
  { label: 'mcp remove', takesServer: true, options: (s) => ({ subcommand: 'mcp', args: ['remove', 'mcp-1'], server: s, json: true }) },
  { label: 'mcp attach', takesServer: true, options: (s) => ({ subcommand: 'mcp', args: ['attach'], server: s, dir: projectDir, json: true }) },
  { label: 'activity', takesServer: true, options: (s) => ({ subcommand: 'activity', server: s, json: true }) },
  { label: 'suspend', takesServer: true, options: (s) => ({ subcommand: 'suspend', server: s, json: true }) },
  { label: 'reactivate', takesServer: true, options: (s) => ({ subcommand: 'reactivate', server: s, json: true }) },
  { label: 'revoke --ci', takesServer: true, options: (s) => ({ subcommand: 'revoke', server: s, ci: true, json: true }) },
];

const COLUMNS: Column[] = [
  { server: 'A', typed: false },
  { server: 'B', typed: false },
  { typed: false },
  { server: 'A', typed: true },
  { server: 'B', typed: true },
];

const isConnect = (command: Command) => command.label.startsWith('connect');

const LATER = new Date(Date.now() + 3_600_000).toISOString();
const SIGN_IN_HEADERS = ['authorization', 'x-api-key', 'x-aim-api-key'] as const;

let identity: IdentityFn;
let home = '';
let savedHome: string | undefined;
const servers = {} as Record<Label, CaptureServer>;
const stored = {} as Record<Label, StoredFor>;

beforeAll(async () => {
  savedHome = process.env.HOME;
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-identity-two-servers-'));
  // The auth and connection loaders resolve the home directory when they load.
  process.env.HOME = home;
  ({ identity } = await import('../../src/commands/identity.js'));
  servers.A = await startCaptureServer();
  servers.B = await startCaptureServer();
});

afterAll(async () => {
  await servers.A?.close();
  await servers.B?.close();
  process.env.HOME = savedHome;
  fs.rmSync(home, { recursive: true, force: true });
});

beforeEach(() => {
  servers.A.requests.length = 0;
  servers.B.requests.length = 0;
  stored.A = valuesFor('A');
  stored.B = valuesFor('B');
  explicitKey = made('aim', 'key', 'typed');
  fs.rmSync(path.join(home, '.opena2a'), { recursive: true, force: true });
  state.dataDir = fs.mkdtempSync(path.join(home, 'identity-'));
  fs.writeFileSync(path.join(state.dataDir, 'identity.json'), '{}');
  projectDir = fs.mkdtempSync(path.join(home, 'project-'));
  fs.writeFileSync(
    path.join(projectDir, '.mcp.json'),
    JSON.stringify({ mcpServers: { 'probe-mcp': { command: 'node', args: ['server.js'] } } }),
  );
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Write the login and the agent connection a setup names. */
function writeStore(setup: Setup): void {
  const opena2a = path.join(home, '.opena2a');
  const identities = path.join(opena2a, 'aim-core', 'identities');
  fs.mkdirSync(identities, { recursive: true });
  const login = stored[setup.login];
  fs.writeFileSync(
    path.join(opena2a, 'auth.json'),
    JSON.stringify({
      serverUrl: servers[setup.login].url,
      accessToken: login.loginAccess,
      refreshToken: login.loginRefresh,
      expiresAt: LATER,
      tokenType: 'Bearer',
      authenticatedAt: '2026-10-15T00:00:00.000Z',
      tokenStorage: 'file',
    }),
    { mode: 0o600 },
  );
  const conn = stored[setup.connection];
  fs.writeFileSync(
    path.join(identities, 'server.json'),
    JSON.stringify({
      serverUrl: servers[setup.connection].url,
      agentId: conn.agentId,
      apiKey: conn.apiKey,
      ...(setup.connectionToken ? { accessToken: conn.connectionAccess } : {}),
      registeredAt: '2026-10-15T00:00:00.000Z',
    }),
    { mode: 0o600 },
  );
}

/** The values a setup stored for one server, each with what it is. */
function storedFor(setup: Setup, label: Label): Map<string, string> {
  const v = stored[label];
  const out = new Map<string, string>();
  if (setup.login === label) {
    out.set(v.loginAccess, `the login token stored for ${label}`);
    out.set(v.loginRefresh, `the refresh token stored for ${label}`);
  }
  if (setup.connection === label) {
    out.set(v.apiKey, `the API key stored for ${label}`);
    out.set(v.agentId, `the agent ID stored for ${label}`);
    if (setup.connectionToken) out.set(v.connectionAccess, `the connection token stored for ${label}`);
  }
  return out;
}

const PLACEHOLDER = /^(undefined|null|<[^>]*>)?$/;

/** Every string in a JSON body, at any depth. */
function strings(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(strings);
  if (value && typeof value === 'object') return Object.values(value).flatMap(strings);
  return [];
}

/** What each server received that this file's rules do not allow, in words. */
function problems(setup: Setup, command: Command, column: Column): string[] {
  const found: string[] = [];
  const typedFor = column.typed || isConnect(command) ? column.server : undefined;
  const everything = new Map([...storedFor(setup, 'A'), ...storedFor(setup, 'B')]);
  if (typedFor) everything.set(explicitKey, `the key typed on the command line for ${typedFor}`);
  for (const label of ['A', 'B'] as const) {
    const allowed = storedFor(setup, label);
    if (typedFor === label) allowed.set(explicitKey, `the key typed on the command line for ${label}`);
    for (const req of servers[label].requests) {
      const where = `${label} received ${req.method} ${req.path.split('?')[0]}`;
      const text = [req.path, JSON.stringify(req.headers), req.body].join('\n');
      for (const [value, what] of everything) {
        if (!allowed.has(value) && text.includes(value)) found.push(`${where} carrying ${what}`);
      }
      for (const name of SIGN_IN_HEADERS) {
        const raw = req.headers[name];
        if (raw === undefined) continue;
        const value = String(raw).replace(/^Bearer /, '');
        if (!allowed.has(value) && !everything.has(value)) {
          found.push(`${where} with ${name}: ${JSON.stringify(value)}, which was not stored for ${label}`);
        }
      }
      for (const segment of req.path.split('?')[0].split('/').slice(1)) {
        if (PLACEHOLDER.test(decodeURIComponent(segment))) found.push(`${where} with the path segment ${JSON.stringify(segment)}`);
      }
      if (req.body) {
        for (const s of strings(JSON.parse(req.body))) {
          if (PLACEHOLDER.test(s)) found.push(`${where} with ${JSON.stringify(s)} as a value`);
        }
      }
    }
  }
  if (column.server && command.takesServer) {
    const other: Label = column.server === 'A' ? 'B' : 'A';
    for (const req of servers[other].requests) {
      found.push(`given ${column.server}, ${other} received ${req.method} ${req.path.split('?')[0]}`);
    }
  }
  return found;
}

for (const setup of SETUPS) {
  describe(setup.name, () => {
    for (const command of COMMANDS) {
      // connect is always run with --api-key.
      for (const column of COLUMNS.filter((c) => !(isConnect(command) && c.typed))) {
        const flag = isConnect(command)
          ? column.server ? `<url> ${column.server}` : 'no <url>'
          : `${column.server ? `--server ${column.server}` : 'no --server'}${column.typed ? ' --api-key <typed>' : ''}`;
        it(`identity ${command.label}, ${flag}`, async () => {
          writeStore(setup);
          const options = command.options(column.server ? servers[column.server].url : undefined);
          await identity(column.typed ? { ...options, apiKey: explicitKey } : options);
          const found = problems(setup, command, column);
          expect(found, found.join('; ')).toEqual([]);
        });
      }
    }
  });
}

describe('the matrix reaches the servers', () => {
  // A matrix in which no command sends a request would pass every cell.
  it('a command run with what is stored for A sends A its agent ID and its sign-in', async () => {
    writeStore(SETUPS[0]);
    await identity({ subcommand: 'trust', server: servers.A.url, dir: projectDir, json: true });
    expect(servers.A.requests.map((r) => `${r.method} ${r.path}`)).toEqual([`GET /api/v1/agents/${stored.A.agentId}`]);
    expect(servers.A.requests[0].headers.authorization).toBe(`Bearer ${stored.A.loginAccess}`);
    expect(servers.A.requests[0].headers['x-aim-api-key']).toBe(stored.A.apiKey);
    expect(servers.B.requests).toEqual([]);
  });

  it('a command run against B, with only A stored, sends B nothing', async () => {
    writeStore(SETUPS[0]);
    const code = await identity({ subcommand: 'suspend', server: servers.B.url, json: true });
    expect(code).toBe(1);
    expect(servers.B.requests).toEqual([]);
    expect(servers.A.requests).toEqual([]);
  });
});

describe('the token for the server an agent is connected to', () => {
  it('suspend signs in with the login stored for that server when the connection holds no token', async () => {
    writeStore(SETUPS[0]);
    const code = await identity({ subcommand: 'suspend', json: true });
    expect(code).toBe(0);
    expect(servers.A.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      `POST /api/v1/agents/${stored.A.agentId}/suspend`,
    ]);
    expect(servers.A.requests[0].headers.authorization).toBe(`Bearer ${stored.A.loginAccess}`);
  });
});

describe('stored sign-in is matched by the server origin', () => {
  it('a stored URL with a trailing slash matches --server given as host and port', async () => {
    writeStore(SETUPS[0]);
    const connectionFile = path.join(home, '.opena2a', 'aim-core', 'identities', 'server.json');
    const connection = JSON.parse(fs.readFileSync(connectionFile, 'utf-8'));
    fs.writeFileSync(connectionFile, JSON.stringify({ ...connection, serverUrl: `${servers.A.url}/` }));
    await identity({ subcommand: 'trust', server: servers.A.url.replace('http://', ''), dir: projectDir, json: true });
    expect(servers.A.requests.map((r) => r.path)).toEqual([`/api/v1/agents/${stored.A.agentId}`]);
    expect(servers.A.requests[0].headers.authorization).toBe(`Bearer ${stored.A.loginAccess}`);
  });

  it('the origin is the scheme, host and port, after the --server shortcuts', async () => {
    const { serverOrigin } = await import('../../src/util/identity-auth-lookup.js');
    expect(serverOrigin('https://Aim.Example.Test:443/api/')).toBe('https://aim.example.test');
    expect(serverOrigin('localhost:8080')).toBe('http://localhost:8080');
    expect(serverOrigin('cloud')).toBe('https://aim.oa2a.org');
    expect(serverOrigin('http://127.0.0.1:8080')).not.toBe(serverOrigin('http://127.0.0.1:8081'));
    expect(serverOrigin('http://aim.example.test')).not.toBe(serverOrigin('https://aim.example.test'));
  });
});
