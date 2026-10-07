/**
 * Telemetry and contribution texts make no anonymity claim.
 *
 * Every usage event carries an install ID that identifies the machine, so the
 * data is personal data. Contributed scans carry a contributor token, a hash
 * made on the machine from the hostname, the user name and a random salt. No
 * text listed below may call either of them anonymous, anonymised,
 * irreversible or free of personal data (or of PII), because none of those is
 * true of the install ID and none has been established for the contributor
 * token.
 *
 * The list is explicit, not a walk of the repository: "irreversible" is the
 * correct word elsewhere (the `identity revoke` help, the skill templates),
 * and a repository-wide check would fail on those uses. A file that starts
 * describing telemetry or contribution joins TEXTS.
 *
 * Change logs are records of what a release said, so they are fixed forward
 * and stay out of TEXTS: the telemetry library's 0.2.0 entry keeps the word
 * "irreversible", and its newest section must carry the notice and the
 * correction instead.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');

const BARRED =
  /anonymous|anonymi[sz]ed|irreversib|no personally identif|no personal data|\bno PII\b|does not identify you|cannot identify you/gi;

const TEXTS = [
  'packages/cli/README.md',
  'packages/cli/docs/testing/release-smoke.md',
  'packages/cli/src/index.ts',
  'packages/cli/src/util/report-submission.ts',
  'packages/cli/src/contextual/advisor.ts',
  'packages/cli/src/identity/manifest.ts',
  'packages/cli-ui/src/telemetry-command.ts',
  'packages/contribute/README.md',
  'packages/contribute/src/client.ts',
  'packages/contribute/src/contributor.ts',
  'packages/contribute/src/index.ts',
  'packages/contribute/src/types.ts',
  'packages/shared/README.md',
  'packages/shared/src/user-config.ts',
  'packages/telemetry/package.json',
  'packages/telemetry/src/config.ts',
  'packages/telemetry/src/index.ts',
];

// The sentence that replaces "anonymous" wherever a text describes the
// usage events, and the first 12 hex digits of its SHA-256 as approved.
const INSTALL_ID_SENTENCE =
  'Each event carries an install ID that identifies the machine, so the data is personal data.';
const INSTALL_ID_SENTENCE_SHA256_PREFIX = 'b036246bc8a8';

// The telemetry library's release notice, the first 12 hex digits of its
// SHA-256 as approved, and the sentence that corrects the 0.2.0 entry.
const TELEMETRY_CHANGELOG = 'packages/telemetry/CHANGELOG.md';
const RELEASE_NOTICE =
  "Privacy notice: since May 2026, `hackmyagent`, `opena2a` and `ai-trust` make a new telemetry install ID from the computer's hardware identifier or hostname where one can be used. The privacy policy promised to announce that change before it took effect, and we did not. Details, and how to turn telemetry off: https://opena2a.org/blogs/telemetry-install-id-late-notice";
const RELEASE_NOTICE_SHA256_PREFIX = '9bef4e089611';
const IRREVERSIBLE_CORRECTION =
  'The 0.2.0 entry in this file called the hash irreversible, which was misleading: a hash cannot be run backwards, but anyone who knows or guesses its inputs can compute it again.';

/** The text from the first `## ` heading of a change log up to the next one. */
function newestSection(changelog) {
  const lines = changelog.split('\n');
  const start = lines.findIndex((l) => l.startsWith('## '));
  if (start === -1) return '';
  const next = lines.findIndex((l, i) => i > start && l.startsWith('## '));
  return lines.slice(start, next === -1 ? undefined : next).join('\n');
}

/** One `<file>:<line>: <match>` entry per barred phrase in `text`. */
function barredHits(file, text) {
  const hits = [];
  text.split('\n').forEach((line, i) => {
    for (const m of line.matchAll(BARRED)) hits.push(`${file}:${i + 1}: ${m[0]}`);
  });
  return hits;
}

test('every listed text exists, so a moved file cannot pass by being absent', () => {
  const missing = TEXTS.filter((f) => !existsSync(path.join(REPO_ROOT, f)));
  assert.deepEqual(missing, []);
});

test('no listed telemetry or contribution text calls the data anonymous or the hash irreversible', () => {
  const hits = TEXTS.flatMap((f) => barredHits(f, readFileSync(path.join(REPO_ROOT, f), 'utf8')));
  assert.deepEqual(hits, []);
});

test('the check catches each barred phrase when one is planted', () => {
  const planted = [
    'Tier-1 anonymous usage telemetry SDK for OpenA2A CLIs and tools.',
    'Share anonymized scan results with OpenA2A community',
    'push anonymised results to the OpenA2A Registry',
    'the hash is irreversible',
    'no personally identifying information is collected',
    'No personal data, no source code.',
    '# Registry intelligence (opt-in, no PII, no source code)',
    'a random value that does not identify you',
    'the token cannot identify you',
  ];
  for (const line of planted) {
    assert.equal(barredHits('planted', line).length, 1, line);
  }
});

test('the opena2a README states that each event carries an install ID that identifies the machine', () => {
  assert.equal(
    createHash('sha256').update(INSTALL_ID_SENTENCE).digest('hex').slice(0, 12),
    INSTALL_ID_SENTENCE_SHA256_PREFIX,
  );
  // The README joins the sentence to a pointer at the privacy policy with a
  // semicolon, so everything but its closing period must appear.
  const readme = readFileSync(path.join(REPO_ROOT, 'packages/cli/README.md'), 'utf8');
  assert.ok(readme.includes(INSTALL_ID_SENTENCE.slice(0, -1)));
});

test('the telemetry CHANGELOG carries the install ID notice and the "irreversible" correction in its newest section', () => {
  assert.equal(
    createHash('sha256').update(RELEASE_NOTICE).digest('hex').slice(0, 12),
    RELEASE_NOTICE_SHA256_PREFIX,
  );
  const newest = newestSection(readFileSync(path.join(REPO_ROOT, TELEMETRY_CHANGELOG), 'utf8'));
  assert.ok(newest.includes(RELEASE_NOTICE), 'release notice missing from the newest section');
  assert.ok(newest.includes(IRREVERSIBLE_CORRECTION), 'correction missing from the newest section');
});

test('the CHANGELOG check fails when the notice sits under an older release only', () => {
  const planted = ['# Changelog', '', '## Unreleased', '', '## 0.3.0', '', RELEASE_NOTICE, ''].join('\n');
  assert.equal(newestSection(planted).includes(RELEASE_NOTICE), false);
});
