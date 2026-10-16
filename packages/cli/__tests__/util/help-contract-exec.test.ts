/**
 * Every `Exit codes:` row a subcommand's --help prints is run.
 *
 * The rows live in HELP_CONTRACTS and were written apart from the handlers.
 * help-contract.test.ts checks only their shape, so a row could state an exit
 * status the handler never returns, or leave out a condition it does return,
 * and nothing turned red: the review and detect rows contradicted their
 * handlers three times before they were corrected by hand.
 *
 * Each case below runs the built CLI in a throwaway HOME and project, with
 * every registry and server call pointed at a local stub, and asserts two
 * things: the exit status, and that the row for that status names the
 * condition the case sets up (`when` is quoted from the row's text). A case
 * for a condition the row leaves out therefore fails until the row says it.
 *
 * Every condition of the review and detect rows has its own case. Every row
 * of every other command has at least one case, or is listed in NOT_RUN with
 * the reason it cannot run offline.
 *
 * The engines a command runs are stand-ins on PATH where the command finds
 * them there (ai-trust, docker, python3, and hackmyagent for `check
 * <package>`). The hackmyagent and secretless-ai packages the CLI imports
 * from its own install run for real, on arguments they refuse before doing
 * anything, and a case compares the status with the engine's own. "Not
 * installed" is a resolve hook that makes the package unresolvable.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { HELP_CONTRACTS } from '../../src/util/help-contract.js';

const CLI_PATH = resolve(__dirname, '../../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
const RUN_TIMEOUT = 60_000;
/** A local port nothing listens on: a request to it is refused at once. */
const CLOSED = 'http://127.0.0.1:9';

/** A HOME, a project and a bin directory for one case. */
interface Sandbox {
  base: string;
  home: string;
  project: string;
  bin: string;
  /** The local stub every registry and server call goes to. */
  url: string;
  /** The Unix socket the stub broker listens on. */
  socket: string;
}

interface Run {
  out: string;
  status: number | null;
}

type Cli = (args: string[]) => Promise<Run>;

/** A stub response: status and body. An object is sent as JSON, a string as it is. */
type Route = readonly [status: number, body: unknown];

interface ExitCase {
  /** The words of the row's text this case sets up, quoted from the row. */
  when: string;
  /** Arguments after `opena2a`. */
  args: string[] | ((s: Sandbox) => string[]);
  /** Builds what the case needs before the run; `cli` runs the CLI in the same sandbox. */
  setup?: (s: Sandbox, cli: Cli) => void | Promise<void>;
  /** Stub responses keyed by "METHOD /path"; any other request is answered 404. */
  routes?: Record<string, Route>;
  /** Environment added for the run. */
  env?: (s: Sandbox) => NodeJS.ProcessEnv;
  /** PATH holds the sandbox bin only: no node, npx, which or system tool is found. */
  barePath?: boolean;
  /** Packages the run cannot resolve, as in an install without them. */
  hide?: string[];
  /** For an `engine` row: the status the stand-in engine exits with. */
  status?: number;
  /** For an `engine` row: the engine command whose own status the run must return. */
  engine?: (s: Sandbox) => string[];
  /** Text the output must contain, so the run took the path the case names. */
  output?: RegExp;
  /** For a command that runs until stopped: send SIGINT once this prints. */
  interruptOn?: RegExp;
  /** The case removes a permission, which does not stop root: it is skipped when run as root. */
  permissions?: boolean;
}

const IS_ROOT = process.getuid?.() === 0;

/** Writes `body` to `rel` under the project, creating parent directories. */
function put(s: Sandbox, rel: string, body: string): string {
  const file = join(s.project, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, body);
  return file;
}

/** Writes an executable shell script named `name` into the sandbox bin. */
function tool(s: Sandbox, name: string, body: string): void {
  writeFileSync(join(s.bin, name), `#!/bin/sh\n${body}\n`);
  chmodSync(join(s.bin, name), 0o755);
}

/** Paths a case made unreadable or unwritable; restored before the tree is removed. */
const locked: string[] = [];

function lock(path: string, mode: number): void {
  chmodSync(path, mode);
  locked.push(path);
}

/** A key shaped like an Anthropic API key, built here so no key-shaped literal is committed. */
const FAKE_KEY = 'sk-ant-api03-' + 'A'.repeat(85);

/** A project whose only finding is a hardcoded credential. */
function hardcodedCredential(s: Sandbox): void {
  put(s, 'package.json', '{"name":"cred-test"}\n');
  put(s, '.gitignore', 'node_modules\n');
  put(s, 'config.ts', `const key = "${FAKE_KEY}";\n`);
}

const LOGIN = {
  accessToken: 'test-access-token',
  refreshToken: 'test-refresh-token',
  expiresAt: '2999-01-01T00:00:00.000Z',
  tokenType: 'Bearer',
  authenticatedAt: '2026-01-01T00:00:00.000Z',
};

/** A stored login for the stub server, in the file the CLI writes. */
function storedLogin(s: Sandbox, fields: Record<string, unknown> = { tokenStorage: 'file' }): string {
  const file = join(s.home, '.opena2a', 'auth.json');
  writeFileSync(file, `${JSON.stringify({ serverUrl: s.url, ...LOGIN, ...fields })}\n`);
  return file;
}

/** The agent registration `setup` saves and `watch` and the lifecycle commands read. */
function registeredAgent(s: Sandbox): void {
  const dir = join(s.home, '.opena2a', 'aim-core', 'identities');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'server.json'),
    `${JSON.stringify({ serverUrl: s.url, agentId: 'agent-1', accessToken: LOGIN.accessToken, registeredAt: LOGIN.authenticatedAt })}\n`,
  );
}

/** The user config with community contributions on. */
function contributionsOn(s: Sandbox): void {
  writeFileSync(
    join(s.home, '.opena2a', 'config.json'),
    `${JSON.stringify({ registry: { url: s.url }, contribute: { enabled: true, consentedAt: LOGIN.authenticatedAt, consentVersion: '1.0' } })}\n`,
  );
}

/** An MCP server configuration naming `my-server`. */
function mcpConfig(s: Sandbox, command = 'node'): void {
  put(s, '.mcp.json', `${JSON.stringify({ mcpServers: { 'my-server': { command, args: ['server.js'] } } })}\n`);
}

/** A Shield whose recorded policy hash cannot be parsed: selfcheck reports it compromised. */
function shieldCompromised(s: Sandbox, lockdown: boolean): void {
  const dir = join(s.home, '.opena2a', 'shield');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'policy.yaml'), 'rules: []\n');
  writeFileSync(join(dir, 'policy-hash.json'), 'not json\n');
  if (lockdown) writeFileSync(join(dir, 'lockdown'), '{}\n');
}

/** An ATX the broker is asked to grant, and the broker's token file. */
function grantFiles(s: Sandbox, token = 'test-broker-token'): void {
  put(s, 'atx.json', '{"atcVersion":"1","agentId":"agent-1"}\n');
  put(s, 'broker.token', `${token}\n`);
}

function grantArgs(s: Sandbox, socket = s.socket): string[] {
  return [
    'protect', '--dry-run', '--grant', 'grant://opena2a-protect',
    '--atx', join(s.project, 'atx.json'),
    '--broker-socket', socket, '--broker-token', join(s.project, 'broker.token'),
  ];
}

/** The workspace bin the CLI starts for a package it imports, as adapters/import.ts finds it. */
function workspaceBin(pkg: string): string {
  let dir = dirname(CLI_PATH);
  for (;;) {
    const bin = join(dir, 'node_modules', '.bin', pkg);
    if (existsSync(bin)) return bin;
    const parent = dirname(dir);
    if (parent === dir) throw new Error(`node_modules/.bin/${pkg} not found above ${CLI_PATH}`);
    dir = parent;
  }
}

/** Stand-in engines: answer the availability probe, then exit with the status under test. */
const ENGINE_STATUS = 7;
const aiTrust = (s: Sandbox) => tool(s, 'ai-trust', `exit ${ENGINE_STATUS}`);
const hackmyagent = (s: Sandbox) =>
  tool(s, 'hackmyagent', `[ "$1" = --version ] && { echo 0.30.0; exit 0; }\nexit ${ENGINE_STATUS}`);
const docker = (s: Sandbox, info: number) =>
  tool(s, 'docker', `[ "$1" = info ] && exit ${info}\nexit ${ENGINE_STATUS}`);
const python = (s: Sandbox, importStatus: number) =>
  tool(s, 'python3', `case "$1" in --version) exit 0;; -c) exit ${importStatus};; esac\nexit ${ENGINE_STATUS}`);
/** `npm whoami` and `npm access ls-packages` for an account that can publish demo-pkg. */
const npmOwner = (s: Sandbox) =>
  tool(s, 'npm', `[ "$1" = whoami ] && { echo tester; exit 0; }\n[ "$1" = access ] && { echo '{"demo-pkg":"read-write"}'; exit 0; }\nexit 1`);

const SENSOR_ID = '00000000-0000-4000-8000-000000000001';

const CLAIMED = {
  success: true,
  previousTrustLevel: 'listed',
  newTrustLevel: 'claimed',
  previousTrustScore: 0.5,
  newTrustScore: 0.6,
  profileUrl: 'https://opena2a.org/agents/demo-pkg',
};

const LOOKUP = {
  agentId: 'agent-1',
  name: 'demo-pkg',
  packageType: 'npm',
  source: 'npm',
  trustLevel: 'listed',
  trustScore: 0.8,
  verdict: 'safe',
  publisher: null,
};

/** The device-code login the stub server answers. */
function deviceLogin(expiresIn: number, token: Route): Record<string, Route> {
  return {
    'GET /health': [200, { status: 'ok' }],
    'POST /api/v1/oauth/device/code': [200, {
      deviceCode: 'test-device-code',
      userCode: 'ABCD-1234',
      verificationUri: 'http://127.0.0.1/device',
      verificationUriComplete: 'http://127.0.0.1/device?code=ABCD-1234',
      expiresIn,
      interval: 1,
    }],
    'POST /api/v1/oauth/device/token': token,
  };
}

const TOKEN: Route = [200, { accessToken: 'new-access', refreshToken: 'new-refresh', tokenType: 'Bearer', expiresIn: 3600 }];

/**
 * Cases per command and exit code. The key is the code as the row prints it.
 * review runs with --skip-hma: the scan it skips is started through npx,
 * which would download the scanner.
 */
const CASES: Record<string, Record<string, ExitCase[]>> = {
  review: {
    '0': [
      { when: 'the composite score is 50 or higher', args: ['review', '--skip-hma', '--ci'] },
      { when: 'the composite score is 50 or higher', args: ['review', '--skip-hma', '--ci', '--format', 'json'] },
    ],
    '1': [
      { when: 'the score is below 50', args: ['review', '--skip-hma', '--ci'], setup: hardcodedCredential },
      {
        when: 'the score is below 50',
        args: ['review', '--skip-hma', '--ci', '--format', 'json'],
        setup: hardcodedCredential,
      },
    ],
    '2': [
      { when: 'the directory does not exist', args: (s) => ['review', join(s.project, 'missing'), '--skip-hma', '--ci'] },
      { when: 'an unsupported --format', args: ['review', '--skip-hma', '--ci', '--format', 'sarif'] },
      { when: '--quiet together with --verbose', args: ['review', '--skip-hma', '--ci', '--quiet', '--verbose'] },
      {
        when: 'the HTML report could not be written',
        args: (s) => ['review', '--skip-hma', '--ci', '--report', join(s.project, 'missing', 'report.html')],
      },
      {
        when: 'the HTML report could not be written',
        args: (s) => ['review', '--skip-hma', '--ci', '--format', 'json', '--report', join(s.project, 'missing', 'report.html')],
      },
    ],
  },
  detect: {
    '0': [
      { when: 'discovery finished', args: ['detect', '--ci'] },
      { when: 'discovery finished', args: ['detect', '--ci', '--format', 'json'] },
      {
        when: 'discovery finished',
        args: (s) => ['detect', '--ci', '--report', join(s.project, 'report.html'), '--export-csv', join(s.project, 'assets.csv')],
      },
    ],
    '1': [
      { when: 'the directory cannot be read', args: (s) => ['detect', join(s.project, 'missing'), '--ci'] },
      {
        when: 'the directory cannot be read',
        args: (s) => ['detect', join(s.project, 'locked'), '--ci'],
        permissions: true,
        setup: (s) => {
          mkdirSync(join(s.project, 'locked'));
          lock(join(s.project, 'locked'), 0o000);
        },
      },
      {
        when: 'the --report or --export-csv file could not be written',
        args: (s) => ['detect', '--ci', '--report', join(s.project, 'missing', 'report.html')],
      },
      {
        when: 'the --report or --export-csv file could not be written',
        args: (s) => ['detect', '--ci', '--export-csv', join(s.project, 'missing', 'assets.csv')],
      },
    ],
    '2': [
      { when: 'an unsupported --format', args: ['detect', '--ci', '--format', 'sarif'] },
    ],
  },
  scan: {
    engine: [{
      when: 'the exit status of hackmyagent secure, passed through unchanged',
      args: ['scan', '--no-such-option'],
      engine: () => [workspaceBin('hackmyagent'), 'secure', '--no-such-option'],
      output: /unknown option '--no-such-option'/,
    }],
    '1': [{
      when: 'hackmyagent is not installed or could not start',
      args: ['scan'],
      hide: ['hackmyagent'],
      output: /scan is not installed/,
    }],
  },
  rollback: {
    engine: [{
      when: 'the exit status of hackmyagent rollback, passed through unchanged',
      args: ['rollback', '--no-such-option'],
      engine: () => [workspaceBin('hackmyagent'), 'rollback', '--no-such-option'],
      output: /unknown option '--no-such-option'/,
    }],
    '1': [{
      when: 'hackmyagent is not installed or could not start',
      args: ['rollback'],
      hide: ['hackmyagent'],
      output: /rollback is not installed/,
    }],
  },
  'fix-all': {
    engine: [{
      when: 'the exit status of hackmyagent fix-all, passed through unchanged',
      args: ['fix-all', '--no-such-option'],
      engine: () => [workspaceBin('hackmyagent'), 'fix-all', '--no-such-option'],
      output: /unknown option '--no-such-option'/,
    }],
    '1': [{
      when: 'hackmyagent is not installed or could not start',
      args: ['fix-all'],
      hide: ['hackmyagent'],
      output: /fix-all is not installed/,
    }],
  },
  nanomind: {
    engine: [{
      when: 'the exit status of hackmyagent nanomind, passed through unchanged',
      args: ['nanomind', '--no-such-option'],
      engine: () => [workspaceBin('hackmyagent'), 'nanomind', '--no-such-option'],
      output: /unknown option '--no-such-option'/,
    }],
    '1': [{
      when: 'hackmyagent is not installed or could not start',
      args: ['nanomind', 'status'],
      hide: ['hackmyagent'],
      output: /nanomind is not installed/,
    }],
  },
  secrets: {
    engine: [{
      when: 'the exit status of secretless-ai, passed through unchanged',
      args: ['secrets', 'no-such-command'],
      engine: () => [workspaceBin('secretless-ai'), 'no-such-command'],
      output: /Unknown command: no-such-command/,
    }],
    '1': [{
      when: 'secretless-ai is not installed or could not start',
      args: ['secrets', 'status'],
      hide: ['secretless-ai'],
      output: /secrets is not installed/,
    }],
  },
  broker: {
    engine: [{
      when: 'the exit status of secretless-ai broker, passed through unchanged',
      args: ['broker', '--no-such-option'],
      engine: () => [workspaceBin('secretless-ai'), 'broker', '--no-such-option'],
      output: /Unknown option: --no-such-option/,
    }],
    '1': [{
      when: 'secretless-ai is not installed or could not start',
      args: ['broker', 'status'],
      hide: ['secretless-ai'],
      output: /broker is not installed/,
    }],
  },
  registry: {
    engine: [{
      when: 'the exit status of ai-trust check, passed through unchanged',
      args: ['registry', 'express'],
      setup: aiTrust,
      status: ENGINE_STATUS,
    }],
    '0': [{ when: 'no package name was given (usage is printed)', args: ['registry'], output: /Usage: opena2a registry/ }],
    '1': [{
      when: 'ai-trust is not installed or could not start',
      args: ['registry', 'express'],
      barePath: true,
      output: /registry is not installed/,
    }],
  },
  publish: {
    engine: [{
      when: 'the exit status of ai-trust check, passed through unchanged',
      args: ['publish', 'demo-pkg'],
      setup: aiTrust,
      status: ENGINE_STATUS,
    }],
    '1': [{
      when: 'ai-trust is not installed or could not start',
      args: ['publish', 'demo-pkg'],
      barePath: true,
      output: /registry is not installed/,
    }],
  },
  train: {
    engine: [{
      when: 'the exit status of the opena2a/dvaa container, passed through unchanged',
      args: ['train'],
      setup: (s) => docker(s, 0),
      status: ENGINE_STATUS,
    }],
    '1': [
      { when: 'Docker is not installed or not running', args: ['train'], barePath: true, output: /train is not installed/ },
      { when: 'Docker is not installed or not running', args: ['train'], setup: (s) => docker(s, 1), output: /train is not installed/ },
    ],
  },
  crypto: {
    engine: [{
      when: 'the exit status of cryptoserve, passed through unchanged',
      args: ['crypto', 'scan'],
      setup: (s) => python(s, 0),
      status: ENGINE_STATUS,
    }],
    '1': [{
      when: 'the cryptoserve Python module is not installed or could not start',
      args: ['crypto', 'scan'],
      setup: (s) => python(s, 1),
      output: /crypto is not installed/,
    }],
  },
  check: {
    engine: [
      {
        when: 'the exit status of hackmyagent (check for a package or repository',
        args: ['check', 'express'],
        setup: hackmyagent,
        status: ENGINE_STATUS,
      },
      {
        when: 'secure for a directory), passed through unchanged',
        args: ['check', '.', '--no-such-option'],
        engine: () => [workspaceBin('hackmyagent'), 'secure', '.', '--no-such-option'],
        output: /unknown option '--no-such-option'/,
      },
    ],
    '1': [
      { when: 'the target is not a recognised form', args: ['check', 'example.invalid'], output: /Unknown target/ },
      { when: 'hackmyagent could not start for a directory', args: ['check', '.'], hide: ['hackmyagent'], output: /scan is not installed/ },
    ],
    '254': [
      {
        when: 'hackmyagent is not on PATH for a package or repository',
        args: ['check', 'express'],
        barePath: true,
        output: /hackmyagent is not installed/,
      },
      {
        when: 'also when the npx fallback then runs it',
        args: ['check', 'express'],
        barePath: true,
        setup: (s) => tool(s, 'npx', 'echo "npx ran: $*"\nexit 0'),
        output: /npx ran: hackmyagent check express/,
      },
    ],
  },
  telemetry: {
    '0': [
      { when: 'the setting was shown or changed', args: ['telemetry', 'status'] },
      { when: 'the setting was shown or changed', args: ['telemetry', 'off'] },
      { when: 'also for an unknown action', args: ['telemetry', 'no-such-action'], output: /Unknown action/ },
    ],
    '1': [{
      when: 'the telemetry config file could not be written',
      args: ['telemetry', 'off'],
      setup: (s) => writeFileSync(join(s.home, 'not-a-directory'), ''),
      env: (s) => ({ XDG_CONFIG_HOME: join(s.home, 'not-a-directory') }),
    }],
  },
  protect: {
    '0': [
      { when: 'nothing found', args: ['protect', '--dry-run'] },
      { when: 'nothing found', args: ['protect', '--ci'] },
      { when: 'a --dry-run that found text credentials', args: ['protect', '--dry-run'], setup: hardcodedCredential },
      {
        // The vault is unreachable, so the credential goes to the shell profile in the sandbox HOME.
        when: 'credentials migrated',
        args: ['protect', '--ci', '--skip-liveness', '--skip-sign', '--skip-git', '--skip-verify'],
        setup: hardcodedCredential,
        output: /1 migrated/,
      },
      {
        when: 'or no store accepted a credential, which is then reported as skipped and stays in the source',
        args: ['protect', '--ci', '--skip-liveness', '--skip-sign', '--skip-git', '--skip-verify'],
        setup: (s) => {
          hardcodedCredential(s);
          // The shell profile the fallback appends to is a directory.
          mkdirSync(join(s.home, '.bashrc'));
        },
        output: /1 skipped/,
      },
    ],
    '1': [
      {
        when: 'a migration failed',
        args: ['protect', '--ci', '--skip-liveness', '--skip-sign', '--skip-git', '--skip-verify'],
        permissions: true,
        setup: (s) => {
          hardcodedCredential(s);
          // Stored, but the source file cannot be rewritten.
          lock(join(s.project, 'config.ts'), 0o444);
        },
        output: /1 failed/,
      },
      { when: 'the directory does not exist', args: (s) => ['protect', join(s.project, 'missing')] },
      {
        when: 'no text credential was found but key files were that protect cannot migrate (also with --dry-run)',
        args: ['protect', '--dry-run'],
        setup: (s) => { put(s, 'cert.crt', 'placeholder, not a certificate\n'); },
      },
      {
        when: 'no text credential was found but key files were that protect cannot migrate',
        args: ['protect', '--ci'],
        setup: (s) => { put(s, 'cert.crt', 'placeholder, not a certificate\n'); },
      },
    ],
    '2': [
      { when: 'cannot prompt (stdin is not a terminal and --ci was not given)', args: ['protect'], setup: hardcodedCredential },
      { when: 'the --atx file for --grant is missing or invalid', args: ['protect', '--grant', 'grant://opena2a-protect'] },
      {
        when: 'the --atx file for --grant is missing or invalid',
        args: (s) => ['protect', '--grant', 'grant://opena2a-protect', '--atx', join(s.project, 'missing.json')],
      },
      {
        when: 'the --atx file for --grant is missing or invalid',
        args: (s) => ['protect', '--grant', 'grant://opena2a-protect', '--atx', join(s.project, 'atx.json')],
        setup: (s) => { put(s, 'atx.json', '{"agentId":"agent-1"}\n'); },
      },
    ],
    '3': [{
      when: 'the broker denied the --grant',
      args: (s) => grantArgs(s),
      setup: (s) => grantFiles(s),
      routes: { 'POST /grant': [403, { error: 'denied' }] },
    }],
    '4': [
      { when: 'the broker is unreachable', args: (s) => grantArgs(s, join(s.base, 'no-broker.sock')), setup: (s) => grantFiles(s) },
      {
        when: 'rejected the token (401)',
        args: (s) => grantArgs(s),
        setup: (s) => grantFiles(s),
        routes: { 'POST /grant': [401, { error: 'unauthorized' }] },
      },
      {
        when: 'answered 200 without a JSON body',
        args: (s) => grantArgs(s),
        setup: (s) => grantFiles(s),
        routes: { 'POST /grant': [200, 'granted'] },
      },
    ],
    '5': [{
      when: 'the --grant check failed unexpectedly',
      args: (s) => grantArgs(s),
      // A token with a line break inside cannot be sent as a header.
      setup: (s) => grantFiles(s, 'first-line\nsecond-line'),
      routes: { 'POST /grant': [200, { result: {} }] },
      output: /AAP gate failed unexpectedly/,
    }],
    '6': [{
      when: 'the broker answered with a status other than 200, 401 or 403',
      args: (s) => grantArgs(s),
      setup: (s) => grantFiles(s),
      routes: { 'POST /grant': [500, { error: 'broken' }] },
    }],
  },
  comply: {
    '0': [{
      when: 'CLEAN: no findings, safe to forward',
      args: (s) => ['comply', join(s.project, 'clean.txt')],
      setup: (s) => { put(s, 'clean.txt', 'The meeting is at noon.\n'); },
    }],
    '1': [{
      when: 'VIOLATION or DENY: findings present',
      args: (s) => ['comply', join(s.project, 'ssn.txt')],
      setup: (s) => { put(s, 'ssn.txt', 'My SSN is 123-45-6789\n'); },
    }],
    '2': [
      { when: 'a bad or oversize path', args: (s) => ['comply', join(s.project, 'missing.txt')] },
      {
        when: 'a bad or oversize path',
        args: (s) => ['comply', join(s.project, 'large.txt')],
        setup: (s) => { put(s, 'large.txt', 'a'.repeat(5 * 1024 * 1024 + 1)); },
      },
      { when: 'a read error', args: (s) => ['comply', join(s.project, 'folder')], setup: (s) => mkdirSync(join(s.project, 'folder')) },
      {
        when: 'a read error',
        args: (s) => ['comply', join(s.project, 'unreadable.txt')],
        permissions: true,
        setup: (s) => lock(put(s, 'unreadable.txt', 'text\n'), 0o000),
      },
    ],
  },
  status: {
    '0': [{ when: 'the status was printed', args: ['status'] }],
    '1': [{ when: 'the directory cannot be accessed', args: (s) => ['status', join(s.project, 'missing')] }],
  },
  init: {
    '0': [{ when: 'the assessment ran and found no critical next step', args: ['init', '--ci'] }],
    '1': [
      { when: 'a critical next step was found', args: ['init', '--ci'], setup: hardcodedCredential },
      { when: 'the directory does not exist', args: (s) => ['init', join(s.project, 'missing')] },
    ],
  },
  guard: {
    '0': [
      { when: 'the subcommand succeeded', args: ['guard', 'sign'], setup: (s) => { put(s, 'package.json', '{"name":"demo"}\n'); } },
      {
        when: 'the files verify clean',
        args: ['guard', 'verify'],
        setup: async (s, cli) => {
          put(s, 'package.json', '{"name":"demo"}\n');
          expect((await cli(['guard', 'sign'])).status).toBe(0);
        },
      },
    ],
    '1': [
      {
        when: 'tampered',
        args: ['guard', 'verify'],
        setup: async (s, cli) => {
          put(s, 'package.json', '{"name":"demo"}\n');
          expect((await cli(['guard', 'sign'])).status).toBe(0);
          put(s, 'package.json', '{"name":"changed"}\n');
        },
      },
      {
        when: 'changes found by diff',
        args: ['guard', 'diff'],
        setup: async (s, cli) => {
          put(s, 'package.json', '{"name":"demo"}\n');
          expect((await cli(['guard', 'sign'])).status).toBe(0);
          put(s, 'package.json', '{"name":"changed"}\n');
        },
      },
      { when: 'no signature store', args: ['guard', 'verify'], setup: (s) => { put(s, 'package.json', '{"name":"demo"}\n'); } },
      { when: 'no signature store', args: ['guard', 'verify', '--enforce'], setup: (s) => { put(s, 'package.json', '{"name":"demo"}\n'); } },
      { when: 'an unknown subcommand', args: ['guard', 'no-such-subcommand'] },
    ],
    '3': [{
      when: 'verify --enforce found tampered, missing or unsigned files',
      args: ['guard', 'verify', '--enforce'],
      setup: async (s, cli) => {
        put(s, 'package.json', '{"name":"demo"}\n');
        expect((await cli(['guard', 'sign'])).status).toBe(0);
        put(s, 'package.json', '{"name":"changed"}\n');
      },
    }],
  },
  runtime: {
    '0': [{ when: 'the subcommand succeeded', args: ['runtime', 'init'] }],
    '1': [
      { when: 'a missing or unknown subcommand', args: ['runtime'] },
      { when: 'a missing or unknown subcommand', args: ['runtime', 'no-such-subcommand'] },
      { when: 'no ARP configuration', args: ['runtime', 'start'], output: /No ARP configuration found/ },
    ],
  },
  login: {
    '0': [
      { when: 'logged in', args: (s) => ['login', '--server', s.url], routes: deviceLogin(30, TOKEN), output: /Authenticated to/ },
      { when: 'already logged in to this server', args: (s) => ['login', '--server', s.url], setup: (s) => { storedLogin(s); } },
    ],
    '1': [
      { when: 'login failed', args: ['login', '--server', CLOSED], output: /Cannot reach AIM server/ },
      {
        when: 'was denied',
        args: (s) => ['login', '--server', s.url],
        routes: deviceLogin(30, [400, { error: 'access_denied' }]),
        output: /Login was denied/,
      },
      {
        when: 'timed out',
        args: (s) => ['login', '--server', s.url],
        routes: deviceLogin(1, [400, { error: 'authorization_pending' }]),
        output: /Login timed out/,
      },
      { when: '--ci was given without a stored login', args: (s) => ['login', '--ci', '--server', s.url] },
    ],
  },
  logout: {
    '0': [
      { when: 'stored credentials were removed', args: ['logout'], setup: (s) => { storedLogin(s); } },
      { when: 'or there were none', args: ['logout'] },
    ],
    '1': [{
      when: 'the stored login file could not be removed',
      args: ['logout'],
      permissions: true,
      setup: (s) => {
        storedLogin(s);
        lock(join(s.home, '.opena2a'), 0o500);
      },
    }],
  },
  whoami: {
    '0': [
      { when: 'the output says whether you are logged in', args: ['whoami'] },
      { when: 'the output says whether you are logged in', args: ['whoami'], setup: (s) => { storedLogin(s); }, output: /Authenticated/ },
      {
        when: 'a login file that cannot be read reads as not logged in',
        args: ['whoami'],
        permissions: true,
        setup: (s) => lock(storedLogin(s), 0o000),
        output: /Not authenticated/,
      },
    ],
    '1': [
      {
        when: 'a login file in the older format could not be rewritten in the current one',
        args: ['whoami'],
        permissions: true,
        // No tokenStorage field: the file is rewritten on read.
        setup: (s) => lock(storedLogin(s, {}), 0o400),
      },
    ],
  },
  identity: {
    '0': [{ when: 'the subcommand succeeded', args: ['identity', 'create', '--name', 'test-agent'] }],
    '1': [
      { when: 'an unknown subcommand', args: ['identity', 'no-such-subcommand'] },
      { when: 'check denied the capability', args: ['identity', 'check', 'db:read'] },
      {
        when: 'verify found an invalid signature',
        args: ['identity', 'verify', '--data', 'hello', '--signature', 'c2lnbmF0dXJl', '--public-key', 'cHVibGljLWtleQ=='],
      },
      { when: 'revoke without --ci or --json', args: ['identity', 'revoke'], setup: registeredAgent },
      { when: 'not logged in', args: ['identity', 'activity'] },
    ],
  },
  shield: {
    '0': [{ when: 'the subcommand succeeded', args: ['shield', 'status'] }],
    '1': [
      { when: 'an unknown subcommand', args: ['shield', 'no-such-subcommand'] },
      { when: 'init found hardcoded credentials', args: ['shield', 'init', '--ci'], setup: hardcodedCredential },
      {
        when: 'suggest, explain or triage have no LLM backend',
        args: ['shield', 'suggest'],
        // The backend probe skips the local assistant CLI when this is set.
        env: () => ({ CLAUDECODE: '1' }),
      },
      {
        when: 'evaluate blocked the action',
        args: ['shield', 'evaluate', '--action', 'process.spawn', '--target', 'curl'],
        setup: (s) => {
          const dir = join(s.home, '.opena2a', 'shield');
          mkdirSync(dir, { recursive: true });
          writeFileSync(join(dir, 'policy.yaml'), '{"version":1,"mode":"enforce","default":{"processes":{"deny":["curl"],"allow":[]}}}\n');
        },
        output: /BLOCKED/,
      },
      {
        when: 'no policy is loaded',
        args: ['shield', 'evaluate', '--action', 'process.spawn', '--target', '/usr/bin/curl'],
        output: /No policy loaded/,
      },
      {
        when: 'selfcheck found Shield compromised or in lockdown',
        args: ['shield', 'selfcheck'],
        setup: (s) => shieldCompromised(s, false),
        output: /COMPROMISED/,
      },
      {
        when: 'recover --verify failed',
        args: ['shield', 'recover', '--verify'],
        setup: (s) => shieldCompromised(s, true),
        output: /Verification failed/,
      },
    ],
  },
  'scan-soul': {
    '0': [{
      when: 'the governance score is 60 or higher',
      args: ['scan-soul'],
      setup: async (_s, cli) => { expect((await cli(['harden-soul'])).status).toBe(0); },
    }],
    '1': [
      { when: 'the score is below 60', args: ['scan-soul'] },
      { when: 'a critical control is missing under --strict', args: ['scan-soul', '--strict'], output: /\[strict\] Failed/ },
      { when: 'the scan failed', args: (s) => ['scan-soul', join(s.project, 'missing')] },
      { when: 'the scanner is unavailable', args: ['scan-soul'], hide: ['hackmyagent'], output: /hackmyagent is not installed/ },
    ],
  },
  'harden-soul': {
    '0': [
      { when: 'the governance file was written', args: ['harden-soul'] },
      { when: 'or previewed with --dry-run', args: ['harden-soul', '--dry-run'] },
      {
        when: 'a directory it cannot write to also exits 0 and reports 0 controls covered',
        args: ['harden-soul'],
        permissions: true,
        setup: (s) => lock(s.project, 0o500),
        output: /Controls covered: 0/,
      },
    ],
    '1': [
      { when: 'the scanner is unavailable', args: ['harden-soul'], hide: ['hackmyagent'], output: /hackmyagent is not installed/ },
    ],
  },
  'harden-skill': {
    '0': [{
      when: 'the skill file was hardened',
      args: ['harden-skill', 'SKILL.md'],
      setup: (s) => { put(s, 'SKILL.md', '---\nname: demo\ndescription: A demo skill\n---\n\n# Demo\n\nRuns a demo.\n'); },
    }],
    '1': [
      { when: 'the file does not exist', args: (s) => ['harden-skill', join(s.project, 'missing.md')] },
      { when: 'no skill file is in the current directory', args: ['harden-skill'] },
    ],
  },
  benchmark: {
    '0': [{ when: 'the benchmark ran', args: ['benchmark'] }],
    '1': [
      { when: 'hackmyagent is unavailable', args: ['benchmark'], hide: ['hackmyagent'] },
      { when: 'the --level is invalid', args: ['benchmark', '--level', 'L9'], output: /Invalid level/ },
    ],
  },
  'self-register': {
    '0': [
      { when: 'or a --dry-run', args: ['self-register', '--dry-run'] },
      {
        when: 'a registration the registry refused or that could not reach it is shown as [SKIP] and still exits 0',
        args: (s) => ['self-register', '--yes', '--skip-scan', '--verbose', '--registry-url', s.url],
        output: /\[SKIP\]/,
      },
    ],
    '1': [{ when: 'no tool matched --only', args: ['self-register', '--dry-run', '--only', 'no-such-tool'] }],
    '2': [{
      when: 'a non-interactive run without --yes',
      args: (s) => ['self-register', '--skip-scan', '--registry-url', s.url],
    }],
  },
  verify: {
    '0': [
      { when: 'had no record or could not be looked up', args: ['verify', '--package', 'hackmyagent'] },
      { when: 'the package is not installed', args: ['verify', '--package', 'no-such-package-installed'] },
      {
        when: 'each hash matched',
        args: ['verify', '--package', 'hackmyagent'],
        routes: { 'GET /api/v1/trust/query': [200, { contentVerification: { status: 'verified' } }] },
      },
    ],
    '1': [{
      when: 'the registry reported that a package entry file hash does not match its record (tamper detected)',
      args: ['verify', '--package', 'hackmyagent'],
      routes: { 'GET /api/v1/trust/query': [200, { contentVerification: { status: 'tamper_detected' } }] },
    }],
  },
  trust: {
    '0': [{
      when: 'the trust profile was found and shown',
      args: ['trust', 'demo-pkg', '--ci'],
      routes: { 'GET /v1/trust/lookup': [200, LOOKUP] },
    }],
    '1': [
      { when: 'an invalid --source', args: ['trust', 'demo-pkg', '--source', 'no-such-source'] },
      { when: 'no package name given or found', args: ['trust', '--ci'] },
      { when: 'the package is not in the registry', args: ['trust', 'demo-pkg', '--ci'] },
      { when: 'the lookup failed', args: ['trust', 'demo-pkg', '--ci', '--registry-url', CLOSED] },
    ],
  },
  claim: {
    '0': [{
      when: 'the claim was registered',
      args: ['claim', 'demo-pkg', '--ci'],
      setup: npmOwner,
      routes: { 'GET /v1/trust/lookup': [200, LOOKUP], 'POST /v1/trust/claim': [200, CLAIMED] },
      output: /Claimed successfully/,
    }],
    '1': [
      { when: 'no package name', args: ['claim', '--ci'] },
      { when: 'the package is not in the registry', args: ['claim', 'demo-pkg', '--ci'] },
      {
        when: 'is already claimed',
        args: ['claim', 'demo-pkg', '--ci'],
        routes: { 'GET /v1/trust/lookup': [200, { ...LOOKUP, trustLevel: 'claimed', publisher: 'someone' }] },
      },
      {
        when: 'ownership could not be verified',
        args: ['claim', 'demo-pkg', '--ci'],
        setup: (s) => tool(s, 'npm', 'exit 1'),
        routes: { 'GET /v1/trust/lookup': [200, LOOKUP] },
      },
      {
        when: 'the claim request failed',
        args: ['claim', 'demo-pkg', '--ci'],
        setup: npmOwner,
        routes: { 'GET /v1/trust/lookup': [200, LOOKUP], 'POST /v1/trust/claim': [500, { error: 'broken' }] },
      },
    ],
  },
  admin: {
    '0': [
      { when: 'or usage was printed as text', args: ['admin'], output: /Usage: opena2a admin sensors/ },
      {
        when: 'the operation succeeded',
        args: (s) => ['admin', 'sensors', 'list-pending', '--api-key', 'test-admin-key', '--registry', s.url],
        routes: { 'GET /internal/telemetry/sensors/pending': [200, { sensors: [] }] },
      },
    ],
    '1': [
      { when: 'no admin key', args: (s) => ['admin', 'sensors', 'list-pending', '--registry', s.url] },
      { when: 'an invalid --registry', args: ['admin', 'sensors', 'list-pending', '--api-key', 'test-admin-key', '--registry', 'http://example.invalid'] },
      {
        when: 'a registry or network error',
        args: (s) => ['admin', 'sensors', 'list-pending', '--api-key', 'test-admin-key', '--registry', s.url],
        routes: { 'GET /internal/telemetry/sensors/pending': [500, { error: 'broken' }] },
      },
      { when: 'a registry or network error', args: ['admin', 'sensors', 'list-pending', '--api-key', 'test-admin-key', '--registry', CLOSED] },
      {
        when: 'approve or reject declined or refused without --yes',
        args: (s) => ['admin', 'sensors', 'approve', SENSOR_ID, '--api-key', 'test-admin-key', '--registry', s.url],
        output: /Re-run with --yes/,
      },
      {
        when: 'an invalid --registry or sensor id',
        args: (s) => ['admin', 'sensors', 'approve', 's-1', '--yes', '--api-key', 'test-admin-key', '--registry', s.url],
        output: /not a valid sensor id/,
      },
      { when: 'a usage error under --json', args: ['admin', '--json'] },
    ],
  },
  baselines: {
    '0': [{
      when: 'observations were collected',
      // Resolved from the CLI's own install, as the handler resolves --package.
      args: ['baselines', '--package', 'commander', '--ci'],
      setup: contributionsOn,
      routes: { 'POST /internal/behavioral-observation': [200, { ok: true }] },
    }],
    '1': [
      { when: 'community contributions are not enabled', args: ['baselines', '--package', 'commander', '--ci'] },
      {
        when: 'the package cannot be resolved from where opena2a-cli is installed',
        args: ['baselines', '--package', 'no-such-package-installed', '--ci'],
        setup: contributionsOn,
      },
      {
        when: 'the package cannot be resolved from where opena2a-cli is installed',
        args: ['baselines', '--package', 'demo-pkg', '--ci'],
        setup: (s) => {
          contributionsOn(s);
          // Installed in the project, which is not where the handler looks.
          put(s, 'node_modules/demo-pkg/package.json', '{"name":"demo-pkg","version":"1.0.0","main":"index.js"}\n');
          put(s, 'node_modules/demo-pkg/index.js', 'module.exports = {};\n');
        },
        output: /Package not found: demo-pkg/,
      },
      { when: 'no --package was given', args: ['baselines'] },
    ],
  },
  setup: {
    '0': [{
      when: 'the agent is set up',
      args: ['setup', '--ci'],
      setup: (s) => { storedLogin(s); },
      routes: { 'POST /api/v1/agents': [201, { id: 'agent-1', trustScore: 50 }] },
    }],
    '1': [
      { when: 'no stored login under --json or --ci', args: ['setup', '--ci'] },
      { when: 'no stored login under --json or --ci', args: ['setup', '--json'] },
      {
        when: 'login failed',
        args: ['setup'],
        // The browser login goes to AIM Cloud; the proxy it is sent through refuses it.
        env: () => ({ HTTPS_PROXY: CLOSED, HTTP_PROXY: CLOSED }),
        output: /Cannot reach AIM server/,
      },
      {
        when: 'the identity could not be created',
        args: ['setup', '--ci'],
        setup: (s) => { storedLogin(s); },
        routes: { 'POST /api/v1/agents': [500, { error: 'broken' }] },
      },
    ],
  },
  watch: {
    '0': [{
      when: 'stopped with Ctrl+C',
      args: ['watch', '--interval', '1'],
      setup: (s) => {
        storedLogin(s);
        registeredAgent(s);
      },
      interruptOn: /Ctrl\+C to stop/,
    }],
    '1': [
      { when: 'not logged in', args: ['watch'] },
      { when: 'or no agent is registered', args: ['watch'], setup: (s) => { storedLogin(s); } },
    ],
  },
  demo: {
    '0': [
      { when: 'the demo finished', args: ['demo', '--ci'] },
      { when: 'the demo finished', args: ['demo', 'dvaa', '--ci'] },
    ],
    '1': [
      { when: 'an unknown scenario', args: ['demo', 'no-such-scenario', '--ci'] },
      { when: 'or the demo failed', args: ['demo', '--ci'], env: (s) => ({ TMPDIR: join(s.base, 'missing') }), output: /Demo error/ },
    ],
  },
  config: {
    '0': [
      { when: 'the setting was changed or shown', args: ['config', 'show'] },
      { when: 'the setting was changed or shown', args: ['config', 'contribute', 'on'] },
      { when: 'the setting was changed or shown', args: ['config', 'llm'] },
    ],
    '1': [
      { when: 'an unknown action', args: ['config', 'no-such-action'] },
      { when: 'an unknown key or value', args: ['config', 'contribute', 'maybe'] },
      { when: 'an unknown key or value', args: ['config', 'set', 'no-such-key', 'on'] },
      { when: 'config set without its key or value', args: ['config', 'set'] },
      { when: 'config set without its key or value', args: ['config', 'set', 'llm'] },
    ],
  },
  skill: {
    '0': [{ when: 'the skill was created', args: ['skill', 'create', 'demo-skill', '--ci'] }],
    '1': [
      { when: 'a missing or unknown subcommand', args: ['skill'] },
      { when: 'a missing or unknown subcommand', args: ['skill', 'no-such-subcommand'] },
      {
        when: 'a non-empty target directory without --force',
        args: ['skill', 'create', 'demo-skill', '--ci'],
        setup: (s) => { put(s, 'demo-skill/notes.txt', 'keep\n'); },
      },
    ],
  },
  mcp: {
    '0': [
      { when: 'the audit finished', args: ['mcp', 'audit'], setup: (s) => mcpConfig(s) },
      { when: 'the server was signed', args: ['mcp', 'sign', 'my-server'], setup: (s) => mcpConfig(s) },
      {
        when: 'or verify passed',
        args: ['mcp', 'verify', 'my-server'],
        setup: async (s, cli) => {
          mcpConfig(s);
          expect((await cli(['mcp', 'sign', 'my-server'])).status).toBe(0);
        },
      },
    ],
    '1': [
      {
        when: 'verify failed',
        args: ['mcp', 'verify', 'my-server'],
        setup: async (s, cli) => {
          mcpConfig(s);
          expect((await cli(['mcp', 'sign', 'my-server'])).status).toBe(0);
          mcpConfig(s, 'python3');
        },
      },
      { when: 'the server or its identity was not found', args: ['mcp', 'sign', 'no-such-server'], setup: (s) => mcpConfig(s) },
      { when: 'the server or its identity was not found', args: ['mcp', 'verify', 'my-server'], setup: (s) => mcpConfig(s) },
      { when: 'no server name was given', args: ['mcp', 'sign'], setup: (s) => mcpConfig(s) },
      { when: 'an unknown subcommand', args: ['mcp', 'no-such-subcommand'] },
    ],
  },
};

/**
 * Rows no case runs, keyed "<command> <code>", with the reason. Listed so a
 * new one is a visible diff, not a silent skip.
 */
const NOT_RUN: Record<string, string> = {};

/**
 * Conditions a row names that no case sets up, keyed "<command> <code>: <the
 * row's words>", with the reason. Their rows run through other conditions.
 */
const CONDITIONS_NOT_RUN: Record<string, string> = {
  'protect 0: you declined at the prompt': 'answering the prompt needs a terminal',
  'protect 2: the prompt was aborted': 'the prompt is shown only on a terminal',
  'protect 4: its socket belongs to another user': 'needs a broker socket at the default path owned by another user',
  'comply 2: no input on a terminal': 'needs stdin to be a terminal',
  'comply 2: a classification failure (fails closed)': 'no input found that makes the classifier throw',
  'runtime 1: monitoring failed to start': 'needs an ARP configuration and starts the monitors on this machine',
  'skill 1: a critical warning in the scaffold': 'only the interactive prompts choose the capabilities that raise one; --ci and CI use the defaults',
  'self-register 2: declined at the prompt': 'the prompt is shown only on a terminal',
  'self-register 1: processing a tool threw an error': 'no input found that makes a tool fail; a registry that refuses or cannot be reached is a [SKIP]',
  'benchmark 1: the run failed': 'no input found that makes the scan throw; a directory that does not exist is benchmarked and exits 0',
  'harden-soul 1: generation failed': 'no input found that makes generation throw; a directory it cannot write to exits 0',
  'guard 1: a declined resign': 'the confirmation is shown only on a terminal',
  'admin 1: approve or reject declined': 'the confirmation is shown only on a terminal; the refusal without --yes runs',
};

/** Commands every condition of whose rows has its own case. */
const EVERY_CONDITION = ['review', 'detect'];

/** The conditions a row's text lists, separated by commas. */
function conditions(text: string): string[] {
  return text.split(/, or |, /);
}

let root: string;
let server: Server;
let broker: Server;
let serverUrl: string;
let brokerSocket: string;
let sandboxCount = 0;
/** The responses the stub gives for the case that is running. */
let routes: Record<string, Route> = {};

/** Answers from `routes`, and 404 with a JSON body for anything else. */
function stub(req: IncomingMessage, res: ServerResponse): void {
  req.resume();
  const route = routes[`${req.method} ${(req.url ?? '').split('?')[0]}`];
  if (!route) {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":"not found"}');
    return;
  }
  const [status, body] = route;
  const json = typeof body !== 'string';
  res.writeHead(status, { 'content-type': json ? 'application/json' : 'text/plain' });
  res.end(json ? JSON.stringify(body) : body);
}

/**
 * A fresh sandbox. The environment is built from scratch, not from
 * process.env, so no login, server, vault, registry or LLM setting of the
 * developer's shell reaches the command, and PATH holds the system
 * directories and node's own, not node_modules/.bin. A request that is not
 * aimed at the local stub goes to a proxy on a closed port.
 */
function makeSandbox(c: ExitCase): { sandbox: Sandbox; env: NodeJS.ProcessEnv; keychainLog: string } {
  const base = join(root, String(++sandboxCount));
  const home = join(base, 'home');
  const project = join(base, 'project');
  const bin = join(base, 'bin');
  for (const dir of [project, bin, join(home, '.opena2a'), join(home, '.secretless-ai')]) {
    mkdirSync(dir, { recursive: true });
  }
  const sandbox: Sandbox = { base, home, project, bin, url: serverUrl, socket: brokerSocket };
  writeFileSync(join(home, '.opena2a', 'config.json'), `${JSON.stringify({ registry: { url: serverUrl } })}\n`);
  // No credential store is reachable: a vault backend with no VAULT_* set
  // fails before any process starts, and the OS keychain tools exit 1 and
  // record that they were started.
  writeFileSync(join(home, '.secretless-ai', 'config.json'), '{"backend":"vault"}\n');
  const keychainLog = join(base, 'keychain-calls');
  for (const name of ['security', 'secret-tool']) tool(sandbox, name, `echo "$0 $*" >> '${keychainLog}'\nexit 1`);
  // A report or login page the command would open in a browser opens nothing.
  for (const name of ['open', 'xdg-open']) tool(sandbox, name, 'exit 0');
  const env: NodeJS.ProcessEnv = {
    PATH: c.barePath ? bin : [bin, dirname(process.execPath), '/usr/bin', '/bin', '/usr/sbin', '/sbin'].join(':'),
    HOME: home,
    TMPDIR: base,
    NODE_OPTIONS: '',
    NO_COLOR: '1',
    OPENA2A_TELEMETRY: 'off',
    OPENA2A_AUTH_FORCE_FILE: '1',
    XDG_CONFIG_HOME: join(home, '.config'),
    HTTPS_PROXY: CLOSED,
    HTTP_PROXY: CLOSED,
    NO_PROXY: '127.0.0.1,localhost,::1',
    NODE_USE_ENV_PROXY: '1',
  };
  if (c.hide) {
    const hook = join(base, 'hide.mjs');
    // A resolve hook that refuses the hidden packages: synchronous where node
    // has registerHooks, the async register() it deprecates otherwise.
    const refuse =
      `const hidden = ${JSON.stringify(c.hide)};\n` +
      'function refuse(specifier) {\n' +
      "  if (hidden.some((n) => specifier === n || specifier.startsWith(n + '/'))) {\n" +
      "    throw Object.assign(new Error(`Cannot find package '${specifier}'`), { code: 'ERR_MODULE_NOT_FOUND' });\n" +
      '  }\n' +
      '}\n';
    const asyncHook = `${refuse}export async function resolve(s, c, next) { refuse(s); return next(s, c); }\n`;
    writeFileSync(
      hook,
      "import * as mod from 'node:module';\n" +
        refuse +
        "if (typeof mod.registerHooks === 'function') {\n" +
        '  mod.registerHooks({ resolve(s, c, next) { refuse(s); return next(s, c); } });\n' +
        '} else {\n' +
        `  mod.register(${JSON.stringify(`data:text/javascript,${encodeURIComponent(asyncHook)}`)});\n` +
        '}\n',
    );
    env.NODE_OPTIONS = `--import ${pathToFileURL(hook).href}`;
  }
  Object.assign(env, c.env?.(sandbox));
  return { sandbox, env, keychainLog };
}

/** Runs `argv` without blocking the event loop, so the stubs can answer. */
function run(command: string, argv: string[], cwd: string, env: NodeJS.ProcessEnv, interruptOn?: RegExp): Promise<Run> {
  return new Promise((done) => {
    const child = spawn(command, argv, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let interrupted = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), RUN_TIMEOUT);
    const watch = () => {
      if (interruptOn && !interrupted && interruptOn.test(`${stdout}\n${stderr}`.replace(STRIP_ANSI, ''))) {
        interrupted = true;
        child.kill('SIGINT');
      }
    };
    child.stdout.on('data', (d) => { stdout += d; watch(); });
    child.stderr.on('data', (d) => { stderr += d; watch(); });
    child.on('close', (status) => {
      clearTimeout(timer);
      done({ out: `${stdout}\n${stderr}`.replace(STRIP_ANSI, ''), status });
    });
  });
}

/** The row text for `code`, or undefined when the command has no such row. */
function rowText(command: string, code: string): string | undefined {
  return HELP_CONTRACTS[command]?.exit.find(([c]) => c === code)?.[1];
}

/** The sandbox paths as placeholders, for test titles. */
const PLACEHOLDERS: Sandbox = {
  base: '<base>',
  home: '<home>',
  project: '<project>',
  bin: '<bin>',
  url: '<stub>',
  socket: '<broker>',
};

function argsOf(c: ExitCase, s: Sandbox): string[] {
  return typeof c.args === 'function' ? c.args(s) : c.args;
}

beforeAll(async () => {
  // Short: the broker socket path must fit the platform's limit.
  root = mkdtempSync(join(tmpdir(), 'opena2a-exit-'));
  server = createServer(stub);
  await new Promise<void>((ready) => server.listen(0, '127.0.0.1', ready));
  serverUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  brokerSocket = join(root, 'broker.sock');
  broker = createServer(stub);
  await new Promise<void>((ready) => broker.listen(brokerSocket, ready));
});

afterAll(async () => {
  await new Promise<void>((closed) => server.close(() => closed()));
  await new Promise<void>((closed) => broker.close(() => closed()));
  for (const path of locked) {
    try { chmodSync(path, 0o755); } catch { /* already gone */ }
  }
  rmSync(root, { recursive: true, force: true });
});

it('dist/index.js exists', () => {
  expect(existsSync(CLI_PATH)).toBe(true);
});

for (const [command, rows] of Object.entries(CASES)) {
  describe(`${command}: each --help exit-code row is what the command returns`, () => {
    for (const [code, cases] of Object.entries(rows)) {
      for (const c of cases) {
        it.skipIf(c.permissions === true && IS_ROOT)(`exit ${code} (${c.when}): opena2a ${argsOf(c, PLACEHOLDERS).join(' ')}`, async () => {
          const { sandbox, env, keychainLog } = makeSandbox(c);
          routes = c.routes ?? {};
          const cli: Cli = (args) => run(process.execPath, [CLI_PATH, ...args], sandbox.project, env);
          await c.setup?.(sandbox, cli);
          const args = argsOf(c, sandbox);
          const { out, status } = await run(process.execPath, [CLI_PATH, ...args], sandbox.project, env, c.interruptOn);
          let expected = Number(code);
          if (code === 'engine') {
            if (c.engine) {
              const [bin, ...rest] = c.engine(sandbox);
              const own = await run(bin, rest, sandbox.project, env);
              expect(own.status, `the engine run on its own\n${own.out}`).not.toBeNull();
              expected = own.status!;
            } else {
              expected = c.status!;
            }
          }
          expect(status, `opena2a ${args.join(' ')}\n${out}`).toBe(expected);
          if (c.output) expect(out).toMatch(c.output);
          expect(existsSync(keychainLog), 'an OS keychain tool was started').toBe(false);
          const text = rowText(command, code);
          expect(text, `${command} --help prints no exit ${code} row`).toBeDefined();
          expect(text, `the ${command} exit ${code} row does not name this condition`).toContain(c.when);
        }, RUN_TIMEOUT + 5_000);
      }
    }
  });
}

describe('census', () => {
  it('every exit-code row has a case or a NOT_RUN reason', () => {
    const missing = Object.entries(HELP_CONTRACTS).flatMap(([command, contract]) =>
      contract.exit
        .filter(([code]) => !(CASES[command]?.[code]?.length) && !(`${command} ${code}` in NOT_RUN))
        .map(([code, text]) => `${command} ${code}: ${text}`),
    );
    expect(missing).toEqual([]);
  });

  it('every NOT_RUN entry names a row that exists and that no case runs', () => {
    const stale = Object.keys(NOT_RUN).filter((key) => {
      const [command, code] = key.split(' ');
      return rowText(command, code) === undefined || (CASES[command]?.[code]?.length ?? 0) > 0;
    });
    expect(stale).toEqual([]);
  });

  it('every case names a command and an exit code its --help prints', () => {
    const unknown = Object.entries(CASES).flatMap(([command, rows]) =>
      Object.keys(rows).filter((code) => rowText(command, code) === undefined).map((code) => `${command} ${code}`),
    );
    expect(unknown).toEqual([]);
  });

  it('every CONDITIONS_NOT_RUN entry quotes its row and has no case', () => {
    const stale = Object.keys(CONDITIONS_NOT_RUN).filter((key) => {
      const [, command, code, when] = /^(\S+) (\S+): (.+)$/.exec(key) ?? [];
      const text = rowText(command, code);
      return text === undefined || !text.includes(when) || (CASES[command]?.[code] ?? []).some((c) => c.when === when);
    });
    expect(stale).toEqual([]);
  });

  it('every condition a review or detect row lists has its own case', () => {
    const missing = EVERY_CONDITION.flatMap((command) =>
      HELP_CONTRACTS[command].exit.flatMap(([code, text]) => {
        const covered = new Set((CASES[command]?.[code] ?? []).map((c) => c.when));
        return conditions(text).filter((when) => !covered.has(when)).map((when) => `${command} ${code}: ${when}`);
      }),
    );
    expect(missing).toEqual([]);
  });
});
