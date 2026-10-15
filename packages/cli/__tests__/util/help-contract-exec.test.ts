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
 * Every condition of the review and detect rows has its own case.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { HELP_CONTRACTS } from '../../src/util/help-contract.js';

const CLI_PATH = resolve(__dirname, '../../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
const RUN_TIMEOUT = 60_000;

/** A HOME, a project and a bin directory for one case. */
interface Sandbox {
  base: string;
  home: string;
  project: string;
  bin: string;
  /** The local stub every registry and server call goes to. */
  url: string;
}

interface ExitCase {
  /** The words of the row's text this case sets up, quoted from the row. */
  when: string;
  /** Arguments after `opena2a`. */
  args: string[] | ((s: Sandbox) => string[]);
  /** Builds what the case needs in the sandbox before the run. */
  setup?: (s: Sandbox) => void;
}

/** Writes `body` to `rel` under the project, creating parent directories. */
function put(s: Sandbox, rel: string, body: string): void {
  const file = join(s.project, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, body);
}

/** A key shaped like an Anthropic API key, built here so no key-shaped literal is committed. */
const FAKE_KEY = 'sk-ant-api03-' + 'A'.repeat(85);

/** A project whose only finding is a hardcoded credential, which puts the review score below 50. */
function hardcodedCredential(s: Sandbox): void {
  put(s, 'package.json', '{"name":"cred-test"}\n');
  put(s, '.gitignore', 'node_modules\n');
  put(s, 'config.ts', `const key = "${FAKE_KEY}";\n`);
}

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
        setup: (s) => {
          mkdirSync(join(s.project, 'locked'));
          chmodSync(join(s.project, 'locked'), 0o000);
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
};

/** Commands every condition of whose rows has its own case. */
const EVERY_CONDITION = ['review', 'detect'];

/** The conditions a row's text lists, separated by commas. */
function conditions(text: string): string[] {
  return text.split(/, or |, /);
}

let root: string;
let server: Server;
let serverUrl: string;
let sandboxCount = 0;

/** The stub answers every call with 404 and a JSON error body. */
function stub(_req: IncomingMessage, res: ServerResponse): void {
  res.writeHead(404, { 'content-type': 'application/json' });
  res.end('{"error":"not found"}');
}

/**
 * A fresh sandbox. The environment is built from scratch, not from
 * process.env, so no login, server, vault, registry or LLM setting of the
 * developer's shell reaches the command, and PATH holds the system
 * directories and node's own, not node_modules/.bin.
 */
function makeSandbox(): { sandbox: Sandbox; env: NodeJS.ProcessEnv } {
  const base = join(root, String(++sandboxCount));
  const home = join(base, 'home');
  const project = join(base, 'project');
  const bin = join(base, 'bin');
  for (const dir of [project, bin, join(home, '.opena2a'), join(home, '.secretless-ai')]) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(join(home, '.opena2a', 'config.json'), `${JSON.stringify({ registry: { url: serverUrl } })}\n`);
  // No credential store is reachable: a vault backend with no VAULT_* set
  // fails before any process starts, and the OS keychain tools exit 1.
  writeFileSync(join(home, '.secretless-ai', 'config.json'), '{"backend":"vault"}\n');
  for (const tool of ['security', 'secret-tool']) {
    writeFileSync(join(bin, tool), '#!/bin/sh\nexit 1\n');
    chmodSync(join(bin, tool), 0o755);
  }
  // A report the command would open in a browser opens nothing.
  for (const tool of ['open', 'xdg-open']) {
    writeFileSync(join(bin, tool), '#!/bin/sh\nexit 0\n');
    chmodSync(join(bin, tool), 0o755);
  }
  const env: NodeJS.ProcessEnv = {
    PATH: [bin, dirname(process.execPath), '/usr/bin', '/bin', '/usr/sbin', '/sbin'].join(':'),
    HOME: home,
    TMPDIR: base,
    NODE_OPTIONS: '',
    NO_COLOR: '1',
    OPENA2A_TELEMETRY: 'off',
    OPENA2A_AUTH_FORCE_FILE: '1',
    XDG_CONFIG_HOME: join(home, '.config'),
  };
  return { sandbox: { base, home, project, bin, url: serverUrl }, env };
}

/** Runs the built CLI without blocking the event loop, so the stub can answer. */
function runCli(sandbox: Sandbox, env: NodeJS.ProcessEnv, args: string[]): Promise<{ out: string; status: number | null }> {
  return new Promise((done) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], { cwd: sandbox.project, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), RUN_TIMEOUT);
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
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

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'opena2a-help-contract-exec-'));
  server = createServer(stub);
  await new Promise<void>((ready) => server.listen(0, '127.0.0.1', ready));
  serverUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((closed) => server.close(() => closed()));
  // A case that locked a directory leaves it unreadable; unlock before removing.
  const locked = (dir: string) => {
    try { chmodSync(dir, 0o755); } catch { /* already gone */ }
  };
  for (let i = 1; i <= sandboxCount; i++) locked(join(root, String(i), 'project', 'locked'));
  rmSync(root, { recursive: true, force: true });
});

it('dist/index.js exists', () => {
  expect(existsSync(CLI_PATH)).toBe(true);
});

/** The sandbox paths as placeholders, for test titles. */
const PLACEHOLDERS: Sandbox = { base: '<base>', home: '<home>', project: '<project>', bin: '<bin>', url: '<stub>' };

function argsOf(c: ExitCase, s: Sandbox): string[] {
  return typeof c.args === 'function' ? c.args(s) : c.args;
}

for (const [command, rows] of Object.entries(CASES)) {
  describe(`${command}: each --help exit-code row is what the command returns`, () => {
    for (const [code, cases] of Object.entries(rows)) {
      for (const c of cases) {
        it(`exit ${code} (${c.when}): opena2a ${argsOf(c, PLACEHOLDERS).join(' ')}`, async () => {
          const { sandbox, env } = makeSandbox();
          c.setup?.(sandbox);
          const args = argsOf(c, sandbox);
          const { out, status } = await runCli(sandbox, env, args);
          expect(status, `opena2a ${args.join(' ')}\n${out}`).toBe(Number(code));
          const text = rowText(command, code);
          expect(text, `${command} --help prints no exit ${code} row`).toBeDefined();
          expect(text, `the ${command} exit ${code} row does not name this condition`).toContain(c.when);
        }, RUN_TIMEOUT + 5_000);
      }
    }
  });
}

describe('census', () => {
  it('every exit-code row of review and detect has a case', () => {
    const missing = EVERY_CONDITION.flatMap((command) =>
      HELP_CONTRACTS[command].exit
        .filter(([code]) => !(CASES[command]?.[code]?.length))
        .map(([code, text]) => `${command} ${code}: ${text}`),
    );
    expect(missing).toEqual([]);
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
