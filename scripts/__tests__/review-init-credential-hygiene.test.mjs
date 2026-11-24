/**
 * `opena2a review --format json` reports the Credential scan hygiene check in
 * init's words (issue #400). With zero files scanned, init's check reads
 * "no files scanned"; review's read "no findings", which is what a scan that
 * opened files and found nothing says.
 *
 * Runs the built CLI (`packages/cli/dist`), so `npm run build` comes first.
 * HOME and OPENA2A_HOME point into a temporary directory, so no file of the
 * user running the test is read or written; HMA and the advisory request are
 * off, so no network is used.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'index.js');

function runCli(root, args) {
  const home = path.join(root, 'home');
  mkdirSync(home, { recursive: true });
  const res = spawnSync(process.execPath, [CLI, '--format', 'json', ...args], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      HOME: home,
      OPENA2A_HOME: path.join(root, 'opena2a-home'),
      OPENA2A_TELEMETRY: 'off',
      OPENA2A_ADVISORIES: 'off',
      NO_COLOR: '1',
      CI: '1',
    },
    timeout: 120_000,
  });
  const start = res.stdout.indexOf('{');
  assert.ok(start >= 0, `no JSON on stdout for ${args.join(' ')}:\n${res.stdout}\n${res.stderr}`);
  return JSON.parse(res.stdout.slice(start));
}

function credentialCheck(checks) {
  return checks.find((c) => c.label === 'Credential scan');
}

function setup(t, prefix, files) {
  const root = mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'project');
  mkdirSync(target);
  for (const [name, content] of files) writeFileSync(path.join(target, name), content);
  return { root, target };
}

function runBoth(root, target) {
  const init = runCli(root, ['init', '--dir', target]);
  const review = runCli(root, [
    'review', '--dir', target, '--skip-hma', '--no-open',
    '--report', path.join(root, 'report.html'),
  ]);
  return { init: credentialCheck(init.hygieneChecks), review: credentialCheck(review.initData.hygieneChecks) };
}

test('review --format json says "no files scanned" for the Credential scan check, as init does', (t) => {
  // The credential walk opens none of these: an image, a document and a
  // dotfile that is not an .env file.
  const { root, target } = setup(t, 'review-cred-noscan-', [
    ['logo.png', 'PNG'],
    ['guide.pdf', '%PDF-1.4'],
    ['.toolrc', 'x=1\n'],
  ]);
  const { init, review } = runBoth(root, target);
  assert.equal(init.detail, 'no files scanned');
  assert.equal(review.detail, init.detail);
  assert.notEqual(review.status, 'pass');
});

test('review --format json keeps "no findings" for the Credential scan check when a file was read', (t) => {
  const { root, target } = setup(t, 'review-cred-clean-', [['index.js', 'console.log("hello");\n']]);
  const { init, review } = runBoth(root, target);
  assert.equal(init.detail, 'no findings');
  assert.deepEqual(review, init);
});
