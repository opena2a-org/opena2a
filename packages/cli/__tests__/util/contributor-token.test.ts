/**
 * `opena2a telemetry status` is read-only: it prints the contributor token
 * without creating ~/.opena2a/contributor-salt (#469).
 *
 * It used to call `getContributorToken` from @opena2a/contribute, which
 * creates the salt when it is missing, so the first status in a fresh HOME
 * wrote a file. The CLI now reads the salt with its own peek, which must give
 * the token the contribute release this CLI depends on gives for the same salt.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { contributorSaltPath, ensureContributorSalt, peekContributorToken } from '../../src/util/contributor-token.js';

const CLI_ROOT = resolve(__dirname, '../..');
const CLI_PATH = join(CLI_ROOT, 'dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

let sandbox: string;
let home: string;
let savedHome: string | undefined;

beforeEach(() => {
  sandbox = mkdtempSync(join(tmpdir(), 'opena2a-contrib-token-'));
  home = join(sandbox, 'home');
  mkdirSync(home);
  savedHome = process.env.HOME;
  process.env.HOME = home;
});

afterEach(() => {
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  rmSync(sandbox, { recursive: true, force: true });
});

function childEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    NODE_OPTIONS: '',
    NO_COLOR: '1',
    ...extra,
  };
  delete env.XDG_CONFIG_HOME;
  return env;
}

/** The token the installed @opena2a/contribute derives, in a child under the scratch HOME. */
function dependencyToken(): string {
  const res = spawnSync(
    process.execPath,
    ['-e', "process.stdout.write(require('@opena2a/contribute').getContributorToken())"],
    { cwd: CLI_ROOT, encoding: 'utf8', timeout: 60000, env: childEnv() },
  );
  expect(res.status, res.stderr).toBe(0);
  return res.stdout;
}

describe('peekContributorToken', () => {
  it('returns null in a fresh HOME and creates nothing', () => {
    expect(peekContributorToken()).toBeNull();
    expect(readdirSync(home)).toEqual([]);
  });

  it('reads the salt the contribute dependency writes and derives the same token', () => {
    const token = dependencyToken();
    expect(token).toMatch(/^[a-f0-9]{64}$/);
    expect(existsSync(contributorSaltPath())).toBe(true);
    expect(peekContributorToken()).toBe(token);
  });

  it('trims the salt the way the dependency does', () => {
    mkdirSync(join(home, '.opena2a'));
    writeFileSync(contributorSaltPath(), 'ab'.repeat(32) + '\n', { mode: 0o600 });
    expect(peekContributorToken()).toBe(dependencyToken());
  });
});

describe('ensureContributorSalt', () => {
  it('creates the salt the contribute dependency reads, with mode 0600', () => {
    const token = ensureContributorSalt();
    expect(token).toMatch(/^[a-f0-9]{64}$/);
    expect(statSync(contributorSaltPath()).mode & 0o777).toBe(0o600);
    expect(dependencyToken()).toBe(token);
  });

  it('leaves an existing salt as it is', () => {
    const token = dependencyToken();
    const salt = readFileSync(contributorSaltPath(), 'utf-8');
    expect(ensureContributorSalt()).toBe(token);
    expect(readFileSync(contributorSaltPath(), 'utf-8')).toBe(salt);
  });
});

describe('opena2a telemetry status, on and off', () => {
  function run(action: string, telemetry?: string): string {
    const res = spawnSync(process.execPath, [CLI_PATH, 'telemetry', action], {
      encoding: 'utf8',
      timeout: 60000,
      env: childEnv(telemetry === undefined ? {} : { OPENA2A_TELEMETRY: telemetry }),
    });
    expect(res.status, res.stderr).toBe(0);
    return (res.stdout ?? '').replace(STRIP_ANSI, '');
  }
  const status = (telemetry?: string): string => run('status', telemetry);

  it('leaves a fresh HOME empty while telemetry is off', () => {
    const out = status('off');
    expect(out).toContain('contributor_token: none (created on first contribution)');
    expect(readdirSync(home)).toEqual([]);
  });

  it('never creates the contributor salt, whatever the telemetry state', () => {
    status();
    expect(existsSync(join(home, '.opena2a'))).toBe(false);
  });

  it('on and off create no salt in a fresh HOME with telemetry and contribution off', () => {
    for (const action of ['status', 'on', 'off', 'status']) {
      expect(run(action, 'off'), action).toContain('contributor_token: none (created on first contribution)');
      expect(existsSync(contributorSaltPath()), action).toBe(false);
    }
  });

  it('prints the token once a salt exists, and leaves the salt as it was', () => {
    const token = dependencyToken();
    expect(status('off')).toContain(`contributor_token: ${token}`);
    expect(dependencyToken()).toBe(token);
  });
});
