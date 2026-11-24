/**
 * `opena2a review` names a project of no detected type "project" in its
 * verdict (issue #410). The project type of such a directory reads "Unknown",
 * and review compared it with "unknown", so a clean result said
 * "This Unknown looks safe to use".
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

test('review of a clean directory of no known type calls it a project in the verdict', (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'review-unknown-type-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'project');
  const home = path.join(root, 'home');
  mkdirSync(target);
  mkdirSync(home);
  // No package.json, go.mod or Python manifest: the type is not detected.
  writeFileSync(path.join(target, '.gitignore'), '.env\nnode_modules\n');
  writeFileSync(path.join(target, 'run.sh'), 'echo hello\n');

  const res = spawnSync(process.execPath, [
    CLI, 'review', '--dir', target, '--skip-hma', '--no-open',
    '--report', path.join(root, 'report.html'),
  ], {
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

  const verdict = res.stdout.split('\n').find((l) => l.includes('Verdict')) ?? '';
  assert.match(verdict, /looks safe to use/, `no safe verdict:\n${res.stdout}\n${res.stderr}`);
  assert.match(verdict, /This project looks safe to use\./);
  assert.doesNotMatch(res.stdout, /Unknown looks safe/);
});
