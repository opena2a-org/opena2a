/**
 * `opena2a mcp sign` writes no identity file into the project tree.
 *
 * The identity file holds the MCP server's Ed25519 private key. It belongs in
 * the per-project user store, `<OpenA2A user home>/projects/<key>`, where
 * `<key>` is the first 16 hex characters of the SHA-256 of the project's
 * canonical path, and not under `<project>/.opena2a/mcp-identities`, where a
 * `git add .` publishes it.
 *
 * Runs the built CLI (`packages/cli/dist/index.js`), so `npm run build` comes
 * first. HOME and OPENA2A_HOME point into a temporary directory, so no file of
 * the user running the test is read or written.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'index.js');

function setup(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'mcp-sign-store-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const userHome = path.join(root, 'opena2a-home');
  const project = path.join(root, 'project');
  mkdirSync(home);
  mkdirSync(project);
  writeFileSync(
    path.join(project, '.mcp.json'),
    JSON.stringify({ mcpServers: { demo: { command: 'npx', args: ['-y', 'demo-server@1.0.0'] } } }),
  );
  const key = createHash('sha256').update(realpathSync.native(project)).digest('hex').slice(0, 16);
  const storeDir = path.join(userHome, 'projects', key, 'mcp-identities');
  return { home, userHome, project, storeDir };
}

function run(ctx, args) {
  const env = { ...process.env, HOME: ctx.home, USERPROFILE: ctx.home, OPENA2A_HOME: ctx.userHome, DO_NOT_TRACK: '1' };
  const res = spawnSync(process.execPath, [CLI, ...args, '--ci', '--dir', ctx.project], {
    cwd: ctx.project,
    env,
    encoding: 'utf-8',
    timeout: 60_000,
  });
  return { code: res.status, stdout: res.stdout, stderr: res.stderr };
}

test('the built CLI exists (run npm run build first)', () => {
  assert.ok(existsSync(CLI), `${CLI} is missing`);
});

test('mcp sign writes the identity to the project store and nothing into the project tree', (t) => {
  const ctx = setup(t);
  const res = run(ctx, ['mcp', 'sign', 'demo', '--format', 'json']);
  assert.equal(res.code, 0, res.stderr);

  assert.equal(existsSync(path.join(ctx.project, '.opena2a')), false, 'sign wrote .opena2a/ into the project tree');

  const idPath = path.join(ctx.storeDir, 'demo.json');
  assert.ok(existsSync(idPath), `no identity at ${idPath}`);
  const identity = JSON.parse(readFileSync(idPath, 'utf-8'));
  assert.equal(identity.serverName, 'demo');
  assert.ok(identity.privateKey);
  if (process.platform !== 'win32') {
    assert.equal(statSync(idPath).mode & 0o777, 0o600);
  }

  const out = JSON.parse(res.stdout.slice(res.stdout.indexOf('{'), res.stdout.lastIndexOf('}') + 1));
  assert.equal(realpathSync.native(out.identityFile), realpathSync.native(idPath));
  assert.equal(out.containsPrivateKey, true);
  assert.equal(out.legacyIdentityFile, null);
});

test('mcp verify and audit read the identity from the project store', (t) => {
  const ctx = setup(t);
  assert.equal(run(ctx, ['mcp', 'sign', 'demo']).code, 0);

  const verify = run(ctx, ['mcp', 'verify', 'demo', '--format', 'json']);
  assert.equal(verify.code, 0, verify.stdout + verify.stderr);
  assert.match(verify.stdout, /"status": "verified"/);

  const audit = run(ctx, ['mcp', 'audit', '--format', 'json']);
  assert.equal(audit.code, 0, audit.stderr);
  assert.match(audit.stdout, /"signed": 1/);
  assert.match(audit.stdout, /"verified": 1/);
  assert.equal(existsSync(path.join(ctx.project, '.opena2a')), false);
});

test('mcp sign names an identity an older release left in the project tree as a private key', (t) => {
  const ctx = setup(t);
  const legacyDir = path.join(ctx.project, '.opena2a', 'mcp-identities');
  mkdirSync(legacyDir, { recursive: true });
  const legacyPath = path.join(legacyDir, 'demo.json');
  writeFileSync(legacyPath, '{}');

  const res = run(ctx, ['mcp', 'sign', 'demo']);
  assert.equal(res.code, 0, res.stderr);
  assert.match(res.stdout, /still in the project tree and holds a private key/);
  assert.ok(res.stdout.includes(legacyPath), res.stdout);
  assert.ok(existsSync(path.join(ctx.storeDir, 'demo.json')));
});
