/**
 * What `review` and `identity trust` send to the Registry when contribution
 * is on (issue #410): the version of the CLI that ran, not the 0.6.3 written
 * into the source once, and for each finding a category, not the name of the
 * analyzer that found it ("credential-scan", "hma", "shield").
 *
 * Loads the built CLI modules (`packages/cli/dist`), so `npm run build` comes
 * first. The submission module's functions are replaced with a recorder, so
 * nothing is sent; HOME and OPENA2A_HOME point into a temporary directory, so
 * no file of the user running the test is read or written.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI_DIR = path.resolve(HERE, '..', '..', 'packages', 'cli');
const DIST = path.join(CLI_DIR, 'dist');
const require = createRequire(import.meta.url);
const CLI_VERSION = JSON.parse(readFileSync(path.join(CLI_DIR, 'package.json'), 'utf-8')).version;
const ANALYZERS = ['credential-scan', 'hma', 'shield', 'hygiene', 'guard', 'shadow-ai', 'advisories'];

const sent = [];
const submission = require(path.join(DIST, 'util', 'report-submission.js'));
Object.assign(submission, {
  recordScanAndMaybePrompt: async () => undefined,
  isContributeEnabled: async () => true,
  getRegistryUrl: async () => 'https://registry.example.test',
  submitScanReport: async (_url, report) => { sent.push(report); return true; },
});
const { review } = require(path.join(DIST, 'commands', 'review.js'));
const { identity } = require(path.join(DIST, 'commands', 'identity.js'));

/** Runs `fn` with HOME in a temporary directory, output silenced and no network. */
async function isolated(t, fn) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'contributed-summary-'));
  const saved = { HOME: process.env.HOME, OPENA2A_HOME: process.env.OPENA2A_HOME, fetch: globalThis.fetch };
  const out = process.stdout.write;
  const err = process.stderr.write;
  process.env.HOME = root;
  process.env.OPENA2A_HOME = path.join(root, '.opena2a');
  globalThis.fetch = async () => { throw new Error('offline'); };
  process.stdout.write = () => true;
  process.stderr.write = () => true;
  sent.length = 0;
  try {
    return await fn(root);
  } finally {
    process.stdout.write = out;
    process.stderr.write = err;
    globalThis.fetch = saved.fetch;
    for (const k of ['HOME', 'OPENA2A_HOME']) {
      if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
    }
    t.after(() => rmSync(root, { recursive: true, force: true }));
  }
}

test('review sends the CLI version, and a hardcoded key under the Secrets category', async (t) => {
  await isolated(t, async (root) => {
    const dir = path.join(root, 'project');
    mkdirSync(dir);
    writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'revfix', version: '1.0.0' }));
    writeFileSync(path.join(dir, '.gitignore'), 'node_modules\n');
    writeFileSync(path.join(dir, 'config.ts'), `const key = "${'sk-ant-api03-' + 'A'.repeat(85)}";\n`);

    await review({
      targetDir: dir, format: 'text', reportPath: path.join(root, 'review.html'),
      autoOpen: false, skipHma: true, ci: true,
    });
  });

  assert.equal(sent.length, 1);
  const [report] = sent;
  assert.equal(report.scannerVersion, CLI_VERSION);
  const key = report.findings.find(f => f.description === 'config.ts:1');
  assert.ok(key, 'the hardcoded key is among the findings sent');
  assert.equal(key.category, 'Secrets');
  for (const f of report.findings) {
    assert.ok(!ANALYZERS.includes(f.category), `${f.findingId} is sent under the analyzer name ${f.category}`);
  }
});

test('identity trust sends the version of the CLI that ran it', async (t) => {
  let code;
  await isolated(t, async (root) => {
    code = await identity({ subcommand: 'trust', dir: root });
  });

  assert.equal(code, 0);
  assert.equal(sent.length, 1);
  const [report] = sent;
  assert.equal(report.scannerName, 'opena2a-identity');
  assert.equal(report.scannerVersion, CLI_VERSION);
  assert.notEqual(report.scannerVersion, '0.6.3');
});
