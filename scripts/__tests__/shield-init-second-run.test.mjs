/**
 * A second `opena2a shield init` over a directory of skipped files does not
 * call it clean.
 *
 * The first run writes arp.yaml (and CLAUDE.md, through Secretless) into the
 * project. Those are the only files the second run's credential audit reads,
 * and reading files shield init wrote says nothing about the user's code, so
 * they are not counted and the audit still says nothing was scanned. A file
 * the user has since edited is theirs and is counted.
 *
 * Runs the built CLI (`packages/cli/dist/index.js`), so `npm run build` comes
 * first. HOME and OPENA2A_HOME point into a temporary directory, so no file of
 * the user running the test is read or written.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'index.js');

function setup(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'shield-init-second-run-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const userHome = path.join(root, 'opena2a-home');
  const project = path.join(root, 'project');
  mkdirSync(home);
  // Every entry is a file type or folder the credential walk skips.
  mkdirSync(path.join(project, 'node_modules', 'pkg'), { recursive: true });
  writeFileSync(path.join(project, 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
  writeFileSync(path.join(project, 'yarn.lock'), '# yarn lockfile v1\n');
  writeFileSync(path.join(project, 'node_modules', 'pkg', 'index.js'), 'module.exports = 1;\n');
  return { home, userHome, project };
}

function init(ctx) {
  const env = { ...process.env, HOME: ctx.home, USERPROFILE: ctx.home, OPENA2A_HOME: ctx.userHome, DO_NOT_TRACK: '1' };
  const res = spawnSync(process.execPath, [CLI, 'shield', 'init', '--dir', ctx.project], {
    cwd: ctx.project,
    env,
    input: '',
    encoding: 'utf-8',
    timeout: 60_000,
  });
  const out = res.stdout;
  const audit = out.slice(out.indexOf('Step 2: Credential Audit'), out.indexOf('Step 3:'));
  return { code: res.status, audit, stderr: res.stderr };
}

test('the built CLI exists (run npm run build first)', () => {
  assert.ok(existsSync(CLI), `${CLI} is missing`);
});

test('a second shield init over a directory of skipped files does not call it clean', (t) => {
  const ctx = setup(t);

  const first = init(ctx);
  assert.equal(first.code, 0, first.stderr);
  assert.match(first.audit, /No files were scanned for credentials, so this is not a clean result\./);
  assert.ok(existsSync(path.join(ctx.project, 'arp.yaml')), 'the first run wrote no arp.yaml');

  const second = init(ctx);
  assert.equal(second.code, 0, second.stderr);
  assert.doesNotMatch(second.audit, /No hardcoded credentials found/);
  assert.match(second.audit, /No files were scanned for credentials, so this is not a clean result\./);
  assert.match(second.audit, /The only files read were ones shield init wrote \([^)]*arp\.yaml[^)]*\), so they are not counted\./);
});

test('a file shield init wrote and the user then edited is counted', (t) => {
  const ctx = setup(t);

  assert.equal(init(ctx).code, 0);
  appendFileSync(path.join(ctx.project, 'arp.yaml'), 'rules: []\n');

  const second = init(ctx);
  assert.equal(second.code, 0, second.stderr);
  assert.match(second.audit, /No hardcoded credentials found/);
  assert.doesNotMatch(second.audit, /No files were scanned/);
});
