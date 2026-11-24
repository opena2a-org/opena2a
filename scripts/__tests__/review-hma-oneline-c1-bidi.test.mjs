/**
 * The HMA run reason and version that `opena2a review` prints are cleaned by
 * `oneLine` (issue #410). C0 controls were already removed; C1 controls
 * (U+0080-U+009F) and bidi overrides and isolates (U+202A-U+202E,
 * U+2066-U+2069) passed through, so a scanner's output could reorder or hide
 * text in the notice.
 *
 * Loads the built CLI (`packages/cli/dist`), so `npm run build` comes first.
 * `npx` is a stub script on PATH, so no package is fetched and no network is
 * used.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const REVIEW = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'commands', 'review.js');

const UNWANTED = /[\u0080-\u009f\u202a-\u202e\u2066-\u2069]/;

// One of each range, inside words, so a fix that only covers some is caught.
const DIRTY = 'a\u0085b\u009bc\u202ed\u2066e\u2069f\u202ag';

test('HMA version and run reason carry no C1 or bidi characters', { skip: process.platform === 'win32' }, async (t) => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'review-hma-c1-bidi-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const npx = path.join(dir, 'npx');
  writeFileSync(npx, [
    '#!/usr/bin/env node',
    `const dirty = ${JSON.stringify(DIRTY)};`,
    "if (process.argv.includes('--version')) { process.stdout.write('1.0.0 ' + dirty + '\\n'); process.exit(0); }",
    "process.stderr.write('failed ' + dirty + '\\n'); process.exit(2);",
    '',
  ].join('\n'));
  chmodSync(npx, 0o755);

  const savedPath = process.env.PATH;
  process.env.PATH = `${dir}${path.delimiter}${path.dirname(process.execPath)}${path.delimiter}${savedPath ?? ''}`;
  t.after(() => { process.env.PATH = savedPath; });

  const { runHmaPhase } = await import(pathToFileURL(REVIEW).href);
  const data = await runHmaPhase(dir, { timeoutMs: 30_000 });

  assert.equal(data.run.status, 'exitError', JSON.stringify(data.run));
  assert.ok(data.run.version, 'version was read');
  assert.ok(data.run.reason, 'reason was set');
  assert.doesNotMatch(data.run.version, UNWANTED, JSON.stringify(data.run.version));
  assert.doesNotMatch(data.run.reason, UNWANTED, JSON.stringify(data.run.reason));
  assert.match(data.run.reason, /\(failed a b cdefg\)$/);
});
