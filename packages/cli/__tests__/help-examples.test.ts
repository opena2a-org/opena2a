/**
 * Every command a nested --help prints under Examples runs as shown, and
 * --help never runs the command it was asked about.
 *
 * The `opena2a identity <sub> --help` entries were written apart from the
 * handlers and drifted: `identity log --limit 100` answered "Missing required
 * option: --action", `identity sign <file>`, `identity init` and
 * `identity check` hit their handler's usage error, and
 * `identity tag <agent> <label>` printed the tag usage instead of tagging.
 *
 * Separately, help was intercepted only for subcommands with a help entry, so
 * `--help` after any other word the handler accepts ran the command:
 * `opena2a identity revoke --ci --help` revoked the agent on the AIM server.
 *
 * Runs each identity example from the build in a throwaway HOME and project.
 * An outcome that depends on state (not logged in, no server connection, a
 * denied capability, a signature that does not verify) is a run; the
 * handler's usage-error path is a failure.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { IDENTITY_HELP } from '../src/util/subcommand-help.js';

const CLI_PATH = resolve(__dirname, '../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

/** Lines a handler prints when it rejects its input instead of running. */
const USAGE_ERROR = /^(Usage: opena2a |Missing |Unknown identity subcommand|error: (unknown|missing|too many))/m;

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
};

let root: string;
let project: string;
let env: NodeJS.ProcessEnv;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'opena2a-help-examples-'));
  project = join(root, 'project');
  const home = join(root, 'home');
  mkdirSync(project);
  mkdirSync(home);
  writeFileSync(join(project, 'package.json'), '{"name":"demo","version":"1.0.0"}\n');
  // Built from scratch, not from process.env: no login, server or vault
  // setting of the developer's shell reaches the commands under test.
  env = {
    PATH: process.env.PATH,
    HOME: home,
    TMPDIR: root,
    NODE_OPTIONS: '',
    NO_COLOR: '1',
    OPENA2A_TELEMETRY: 'off',
    OPENA2A_AUTH_FORCE_FILE: '1',
    XDG_CONFIG_HOME: join(home, '.config'),
  };
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

function runCli(args: string[]): { out: string; status: number | null } {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: project,
    encoding: 'utf8',
    timeout: 30_000,
    input: '',
    env,
  });
  return { out: `${res.stdout ?? ''}\n${res.stderr ?? ''}`.replace(STRIP_ANSI, ''), status: res.status };
}

/** Option flags the `identity` command parser declares, from its --help. */
function declaredFlags(help: string): Set<string> {
  const flags = new Set<string>();
  for (const m of help.matchAll(/^ {2}(-[^ ].*?)(?: {2,}|$)/gm)) {
    for (const f of m[1].split(/[ ,]+/)) if (f.startsWith('-')) flags.add(f);
  }
  return flags;
}

describe('identity --help examples run as shown', () => {
  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  const examples = Object.values(IDENTITY_HELP).flatMap((h) => h.examples ?? []);

  it('every example uses a flag the identity command parser declares', () => {
    const flags = new Set([...declaredFlags(runCli(['identity', '--help']).out), ...declaredFlags(runCli(['--help']).out)]);
    const undeclared = examples.flatMap((ex) =>
      ex.split(' ').filter((t) => t.startsWith('-') && !flags.has(t)).map((t) => `${ex}: ${t}`),
    );
    expect(undeclared).toEqual([]);
  });

  for (const example of examples) {
    if (example in NOT_RUN) continue;
    it(example, () => {
      expect(example).not.toMatch(/["']/);
      const tokens = example.split(' ');
      expect(tokens[0]).toBe('opena2a');
      const args = tokens.slice(1).map((t) => {
        if (!/^<.*>$/.test(t)) return t;
        expect(SAMPLES[t], `no sample value for ${t}`).toBeDefined();
        return SAMPLES[t];
      });
      const { out, status } = runCli(args);
      expect(status, out).not.toBeNull();
      expect(out.match(USAGE_ERROR)?.[0] ?? null, out).toBeNull();
    });
  }

  it('an example that hits the usage-error path is flagged', () => {
    expect(USAGE_ERROR.test(runCli(['identity', 'log', '--limit', '100']).out)).toBe(true);
  });
});

describe('--help prints help and never runs the command', () => {
  it('identity revoke --ci --help prints the revoke help', () => {
    const { out, status } = runCli(['identity', 'revoke', '--ci', '--help']);
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
      const { out, status } = runCli(args);
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
      const { out, status } = runCli(args);
      expect(status).toBe(1);
      expect(out).toContain(`Unknown ${args[0]} subcommand: ${args[1]}`);
    });
  }

  it('guard . --help prints the status help, the subcommand a path runs', () => {
    const { out, status } = runCli(['guard', '.', '--help']);
    expect(status).toBe(0);
    expect(out.startsWith('Usage: opena2a guard status'), out).toBe(true);
  });
});
