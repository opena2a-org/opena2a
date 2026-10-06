/**
 * Every command a nested --help prints under Examples runs as shown, and
 * --help never runs the command it was asked about.
 *
 * The `opena2a <parent> <sub> --help` entries were written apart from the
 * handlers and drifted: `identity log --limit 100` answered "Missing required
 * option: --action", `identity sign <file>`, `identity init` and
 * `identity check` hit their handler's usage error, `guard policy set strict`
 * answered "Unknown policy action: set" and `guard snapshot take` "Unknown
 * snapshot action: take".
 *
 * Separately, help was intercepted only for subcommands with a help entry, so
 * `--help` after any other word the handler accepts ran the command:
 * `opena2a identity revoke --ci --help` revoked the agent on the AIM server.
 *
 * Runs each example of the guard, shield, identity, runtime, skill and mcp
 * help entries from the build, in a throwaway HOME and project per parent
 * command and in the order the entries list them. An outcome that depends on
 * state (not logged in, no server connection, a denied capability, no LLM
 * backend, nothing to archive) is a run; the handler's usage-error path is a
 * failure.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  GUARD_HELP,
  IDENTITY_HELP,
  MCP_HELP,
  RUNTIME_HELP,
  SHIELD_HELP,
  SKILL_HELP,
  type SubcommandHelpRegistry,
} from '../src/util/subcommand-help.js';

const CLI_PATH = resolve(__dirname, '../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
const RUN_TIMEOUT = 30_000;

/** Lines a handler prints when it rejects its input instead of running. */
const USAGE_ERROR =
  /^(Usage: opena2a |Missing |Unknown ([a-z]+ )?(subcommand|action)|error: (unknown|missing|too many))/m;

/** Sample values for the placeholders an example leaves to the reader. */
const SAMPLES: Record<string, string> = {
  '<sig>': 'c2lnbmF0dXJl',
  '<key>': 'cHVibGljLWtleQ==',
};

/**
 * Examples that are parsed but not run, with the reason. Listed so a new one
 * is a visible diff, not a silent skip.
 */
const NOT_RUN: Record<string, string> = {
  'opena2a identity connect localhost:8080 --api-key <key>': 'registers on the AIM server it names',
  'opena2a runtime start': 'runs until stopped and starts the ARP monitors on this machine',
};

/**
 * Examples that run until stopped, with the line that shows they started.
 * They are stopped once it prints.
 */
const LONG_RUNNING: Record<string, RegExp> = {
  'opena2a guard watch': /Press Ctrl\+C to stop/,
};

const PARENTS: Array<[string, SubcommandHelpRegistry]> = [
  ['identity', IDENTITY_HELP],
  ['guard', GUARD_HELP],
  ['shield', SHIELD_HELP],
  ['runtime', RUNTIME_HELP],
  ['skill', SKILL_HELP],
  ['mcp', MCP_HELP],
];

interface Sandbox {
  project: string;
  env: NodeJS.ProcessEnv;
}

let root: string;
const sandboxes = new Map<string, Sandbox>();

/**
 * A HOME and a project for one parent command. The environment is built from
 * scratch, not from process.env, so no login, server, vault or LLM setting of
 * the developer's shell reaches the commands under test.
 */
function makeSandbox(name: string): Sandbox {
  const base = join(root, name);
  const home = join(base, 'home');
  const project = join(base, 'project');
  const bin = join(base, 'bin');
  for (const dir of [project, bin, join(home, '.opena2a'), join(home, '.secretless-ai')]) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(join(project, 'package.json'), '{"name":"demo","version":"1.0.0"}\n');
  // The MCP server the mcp examples name.
  writeFileSync(
    join(project, '.mcp.json'),
    `${JSON.stringify({ mcpServers: { 'my-server': { command: 'node', args: ['server.js'] } } })}\n`,
  );
  // Registry lookups (the mcp trust scores) go to a closed local port.
  writeFileSync(join(home, '.opena2a', 'config.json'), '{"registry":{"url":"https://127.0.0.1:9"}}\n');
  // No credential store is reachable: a vault backend with no VAULT_* set
  // fails before any process starts, and the OS keychain tools exit 1.
  writeFileSync(join(home, '.secretless-ai', 'config.json'), '{"backend":"vault"}\n');
  for (const tool of ['security', 'secret-tool']) {
    writeFileSync(join(bin, tool), '#!/bin/sh\nexit 1\n');
    chmodSync(join(bin, tool), 0o755);
  }
  const env: NodeJS.ProcessEnv = {
    PATH: `${bin}:${process.env.PATH}`,
    HOME: home,
    TMPDIR: base,
    NODE_OPTIONS: '',
    NO_COLOR: '1',
    OPENA2A_TELEMETRY: 'off',
    OPENA2A_AUTH_FORCE_FILE: '1',
    XDG_CONFIG_HOME: join(home, '.config'),
    // The LLM backend probe skips the local assistant CLI when this is set,
    // and no API key is passed: suggest, explain and triage report that no
    // backend is available instead of calling a model.
    CLAUDECODE: '1',
    // No terminal answers a wizard: `skill create` takes its defaults.
    CI: 'true',
  };
  // A git work tree: `guard sign` skips git-ignored files, and
  // `guard hook install` writes into .git/hooks.
  expect(spawnSync('git', ['init', '-q'], { cwd: project, env }).status).toBe(0);
  return { project, env };
}

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'opena2a-help-examples-'));
  for (const [parent] of PARENTS) sandboxes.set(parent, makeSandbox(parent));
  sandboxes.set('help', makeSandbox('help'));
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

function clean(stdout: string | null, stderr: string | null): string {
  return `${stdout ?? ''}\n${stderr ?? ''}`.replace(STRIP_ANSI, '');
}

function runCli(sandbox: string, args: string[]): { out: string; status: number | null } {
  const { project, env } = sandboxes.get(sandbox)!;
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: project,
    encoding: 'utf8',
    timeout: RUN_TIMEOUT,
    input: '',
    env,
  });
  return { out: clean(res.stdout, res.stderr), status: res.status };
}

/** Runs a command that does not exit by itself and stops it once `ready` prints. */
function runUntil(sandbox: string, args: string[], ready: RegExp): Promise<{ out: string; started: boolean }> {
  const { project, env } = sandboxes.get(sandbox)!;
  return new Promise((done) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], { cwd: project, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let started = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), RUN_TIMEOUT);
    const check = () => {
      if (!started && ready.test(clean(stdout, stderr))) {
        started = true;
        child.kill('SIGTERM');
      }
    };
    child.stdout.on('data', (d) => { stdout += d; check(); });
    child.stderr.on('data', (d) => { stderr += d; check(); });
    child.on('close', () => {
      clearTimeout(timer);
      done({ out: clean(stdout, stderr), started });
    });
  });
}

/** Option flags a command parser declares, from its --help. */
function declaredFlags(help: string): Set<string> {
  const flags = new Set<string>();
  for (const m of help.matchAll(/^ {2}(-[^ ].*?)(?: {2,}|$)/gm)) {
    for (const f of m[1].split(/[ ,]+/)) if (f.startsWith('-')) flags.add(f);
  }
  return flags;
}

function toArgs(example: string): string[] {
  expect(example).not.toMatch(/["']/);
  const tokens = example.split(' ');
  expect(tokens[0]).toBe('opena2a');
  return tokens.slice(1).map((t) => {
    if (!/^<.*>$/.test(t)) return t;
    expect(SAMPLES[t], `no sample value for ${t}`).toBeDefined();
    return SAMPLES[t];
  });
}

it('dist/index.js exists', () => {
  expect(existsSync(CLI_PATH)).toBe(true);
});

for (const [parent, registry] of PARENTS) {
  describe(`${parent} --help examples run as shown`, () => {
    const examples = Object.values(registry).flatMap((h) => h.examples ?? []);

    it(`every example uses a flag the ${parent} command parser declares`, () => {
      const flags = new Set([
        ...declaredFlags(runCli('help', [parent, '--help']).out),
        ...declaredFlags(runCli('help', ['--help']).out),
      ]);
      const undeclared = examples.flatMap((ex) =>
        ex.split(' ').filter((t) => t.startsWith('-') && !flags.has(t)).map((t) => `${ex}: ${t}`),
      );
      expect(undeclared).toEqual([]);
    }, RUN_TIMEOUT);

    for (const example of examples) {
      if (example in NOT_RUN) continue;
      it(example, async () => {
        const args = toArgs(example);
        if (example in LONG_RUNNING) {
          const { out, started } = await runUntil(parent, args, LONG_RUNNING[example]);
          expect(out.match(USAGE_ERROR)?.[0] ?? null, out).toBeNull();
          expect(started, out).toBe(true);
          return;
        }
        const { out, status } = runCli(parent, args);
        expect(status, out).not.toBeNull();
        expect(out.match(USAGE_ERROR)?.[0] ?? null, out).toBeNull();
      }, RUN_TIMEOUT + 5_000);
    }
  });
}

describe('the usage-error check', () => {
  // Examples the help entries showed before they were corrected.
  for (const args of [
    ['identity', 'log', '--limit', '100'],
    ['guard', 'policy', 'set', 'strict'],
    ['guard', 'snapshot', 'take'],
  ]) {
    it(`flags ${args.join(' ')}`, () => {
      expect(USAGE_ERROR.test(runCli('help', args).out)).toBe(true);
    }, RUN_TIMEOUT);
  }

  it('every example that is not run is still a registered example', () => {
    const all = new Set(PARENTS.flatMap(([, r]) => Object.values(r).flatMap((h) => h.examples ?? [])));
    expect(Object.keys({ ...NOT_RUN, ...LONG_RUNNING }).filter((ex) => !all.has(ex))).toEqual([]);
  });
});

describe('--help prints help and never runs the command', () => {
  it('identity revoke --ci --help prints the revoke help', () => {
    const { out, status } = runCli('help', ['identity', 'revoke', '--ci', '--help']);
    expect(status).toBe(0);
    expect(out.startsWith('Usage: opena2a identity revoke')).toBe(true);
    expect(out).not.toContain('Not authenticated');
  });

  // Words the handlers accept that have no help entry of their own.
  for (const args of [
    ['identity', 'show', '--help'],
    ['shield', 'check', '--help'],
    ['admin', 'sensors', 'approve', 's-1', '--yes', '--registry', 'http://127.0.0.1:9', '--help'],
  ]) {
    it(`${args.join(' ')} prints the ${args[0]} help`, () => {
      const { out, status } = runCli('help', args);
      expect(status).toBe(0);
      expect(out.startsWith(`Usage: opena2a ${args[0]} [options]`), out).toBe(true);
    });
  }

  // Words the handlers do not accept answer as they do without --help.
  for (const args of [
    ['guard', 'signs', '--help'],
    ['identity', 'constructor', '--help'],
  ]) {
    it(`${args.join(' ')} names ${args[1]} as unknown and exits 1`, () => {
      const { out, status } = runCli('help', args);
      expect(status).toBe(1);
      expect(out).toContain(`Unknown ${args[0]} subcommand: ${args[1]}`);
    });
  }

  it('guard . --help prints the status help, the subcommand a path runs', () => {
    const { out, status } = runCli('help', ['guard', '.', '--help']);
    expect(status).toBe(0);
    expect(out.startsWith('Usage: opena2a guard status'), out).toBe(true);
  });
});
