/**
 * `opena2a benchmark --format json` does not count the credential controls as
 * evaluated, or as passing, when the credential scan read no file (issue
 * #400). A folder holding only an image used to score Credential Protection
 * 100% over CRED-002/003/004, the same as a project scanned and found clean.
 *
 * Runs the built CLI (`packages/cli/dist`), so `npm run build` comes first.
 * HOME and OPENA2A_HOME point into a temporary directory, so no file of the
 * user running the test is read or written; no network is used.
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
const CREDENTIAL_CONTROLS = ['CRED-002', 'CRED-003', 'CRED-004'];

function setup(t, prefix, files) {
  const root = mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'project');
  mkdirSync(target);
  for (const [name, content] of files) writeFileSync(path.join(target, name), content);
  return { root, target };
}

function benchmarkJson(root, target) {
  const home = path.join(root, 'home');
  mkdirSync(home, { recursive: true });
  const res = spawnSync(process.execPath, [CLI, 'benchmark', target, '--format', 'json'], {
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
  assert.equal(res.status, 0, `benchmark exited ${res.status}:\n${res.stdout}\n${res.stderr}`);
  const start = res.stdout.indexOf('{');
  assert.ok(start >= 0, `no JSON on stdout:\n${res.stdout}\n${res.stderr}`);
  return JSON.parse(res.stdout.slice(start));
}

function credentialCategory(result) {
  const cat = result.categories.find((c) => /credential/i.test(c.name));
  assert.ok(cat, 'no Credential Protection category');
  return cat;
}

test('benchmark --format json does not evaluate the credential controls when no file was scanned', (t) => {
  // The credential walk opens none of these: an image, a document and a
  // dotfile that is not an .env file.
  const { root, target } = setup(t, 'bench-cred-noscan-', [
    ['logo.png', 'PNG'],
    ['guide.pdf', '%PDF-1.4'],
    ['.toolrc', 'x=1\n'],
  ]);
  const noScan = benchmarkJson(root, target);
  const clean = benchmarkJson(...Object.values(
    setup(t, 'bench-cred-clean-', [['index.js', 'console.log("hello");\n']]),
  ));

  for (const id of CREDENTIAL_CONTROLS) {
    assert.ok(noScan.coverage.notEvaluatedIds.includes(id), `${id} counted as evaluated with no file scanned`);
    assert.ok(!clean.coverage.notEvaluatedIds.includes(id), `${id} not evaluated though index.js was scanned`);
  }
  assert.ok(noScan.coverage.evaluated < clean.coverage.evaluated,
    `no-file run evaluated ${noScan.coverage.evaluated}, scanned run ${clean.coverage.evaluated}`);
  assert.ok(!noScan.coverage.sources.includes('credential scan'));
  assert.equal(noScan.summary.passingControls, clean.summary.passingControls - CREDENTIAL_CONTROLS.length);

  const cred = credentialCategory(noScan);
  assert.notEqual(cred.compliance, 100);
  assert.equal(cred.compliance, null);
  assert.equal(credentialCategory(clean).compliance, 100);
  assert.notEqual(noScan.compliance.l1, 100);
});
