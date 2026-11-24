/**
 * The review report's Summary says so when the credential scan read no file
 * (issue #410). A folder holding only files the scan skips used to open on
 * "No findings." with nothing above the score to say the credential check had
 * examined nothing; only the Credentials tab said it.
 *
 * Runs the built CLI (`packages/cli/dist`), so `npm run build` comes first,
 * then renders the report's Overview with the report's own client script
 * against a stub document. HOME and OPENA2A_HOME point into a temporary
 * directory, so no file of the user running the test is read or written; no
 * network is used.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runInNewContext } from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.resolve(HERE, '..', '..', 'packages', 'cli', 'dist');
const CLI = path.join(DIST, 'index.js');
const require = createRequire(import.meta.url);
const { assembleReviewClientScript } = require(path.join(DIST, 'report', 'review-assets.js'));

const NOTICE = 'Credentials: no file was read, so no credential findings is not a clean result. This directory is empty or holds only files the credential check skips.';

/** The report JSON `opena2a review` embeds in the HTML it writes for `files`. */
function reviewReport(t, prefix, files) {
  const root = mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'project');
  mkdirSync(target);
  for (const [name, content] of files) writeFileSync(path.join(target, name), content);
  const home = path.join(root, 'home');
  mkdirSync(home);
  const html = path.join(root, 'review.html');
  const res = spawnSync(process.execPath, [CLI, 'review', target, '--report', html, '--no-open', '--skip-hma', '--ci'], {
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
  assert.ok(existsSync(html), `review wrote no report (exit ${res.status}):\n${res.stdout}\n${res.stderr}`);
  const m = /<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/.exec(readFileSync(html, 'utf8'));
  assert.ok(m, 'no report data in the HTML report');
  return JSON.parse(m[1]);
}

/** The Summary's visible text, rendered by the report's own client script. */
function summaryText(report) {
  const pages = {};
  const document = {
    getElementById(id) {
      if (id === 'report-data') return { textContent: JSON.stringify(report) };
      if (id === 'main-nav') return { addEventListener() {} };
      return (pages[id] ??= { innerHTML: '', querySelectorAll: () => [] });
    },
    querySelectorAll: () => [],
  };
  runInNewContext(assembleReviewClientScript(), { document, window: { addEventListener() {} } });
  const html = pages['page-overview'].innerHTML;
  const summary = /<section class="card summary"[\s\S]*?<\/section>/.exec(html);
  assert.ok(summary, 'no Summary in the Overview');
  return summary[0].replace(/<[^>]+>/g, ' ').replace(/&#39;/g, "'").replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
}

test('the Summary notes a credential scan that read no file, and only then', (t) => {
  // The credential walk opens none of these: an image, a document and a
  // dotfile that is not an .env file.
  const skipped = reviewReport(t, 'review-sum-noscan-', [
    ['logo.png', 'PNG'],
    ['guide.pdf', '%PDF-1.4'],
    ['.toolrc', 'x=1\n'],
  ]);
  assert.equal(skipped.credentialData.filesScanned, 0);
  const noScan = summaryText(skipped);
  assert.ok(noScan.includes(NOTICE), `no notice in the Summary: ${noScan}`);
  assert.ok(noScan.includes('0 files read for credentials.'), noScan);

  const read = reviewReport(t, 'review-sum-clean-', [['index.js', 'console.log("hello");\n']]);
  assert.ok(read.credentialData.filesScanned > 0);
  const clean = summaryText(read);
  assert.ok(!clean.includes('no file was read'), `notice shown though index.js was read: ${clean}`);
});
