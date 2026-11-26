/**
 * The review report's Summary and Fix first look values from the report up in
 * plain maps: the count for each severity, the label and tab for each source,
 * the finding for each fingerprint. A value that is also a name on
 * Object.prototype, such as "constructor", read the inherited function before:
 * the counts line printed "function Object() { [native code] }1" and the
 * finding after Fix first was listed under an "undefined" tab (issue #410).
 *
 * Runs the built client script (`packages/cli/dist`) against a stub document,
 * so `npm run build` comes first. No file is written and no process is started.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.resolve(HERE, '..', '..', 'packages', 'cli', 'dist', 'report');
const require = createRequire(import.meta.url);
const { assembleReviewClientScript } = require(path.join(DIST, 'review-assets.js'));

/** The Overview's markup, rendered by the report's own client script. */
function overviewHtml(report) {
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
  return pages['page-overview'].innerHTML;
}

/** Visible text: tags dropped, entities decoded, whitespace collapsed. */
function overviewText(report) {
  return overviewHtml(report).replace(/<[^>]+>/g, ' ').replace(/&quot;/g, '"').replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ').trim();
}

const finding = (fingerprint, severity, source) => ({
  fingerprint, title: `Finding ${fingerprint}`, severity, confidence: 'confirmed', category: 'Configuration',
  foundBy: [{ source, checkId: 'X-1', lines: [] }], locations: [], evidence: [], reason: null,
  fix: null, then: null, verify: null, advice: 'Fix it.', recovery: { kind: 'nextRun', points: null, from: 80, to: null },
  occurrences: 1,
});

const report = (reportFindings, fixFirst) => ({
  projectName: 'x', directory: '/tmp/x', timestamp: '2026-11-24T00:00:00Z', compositeScore: 80, provisional: false,
  phases: [{ name: 'HMA Scan', status: 'pass', score: 80, durationMs: 1000, detail: '' }],
  reportFindings, fixFirst, optionalHardening: [],
  scoreModel: { weightSet: 'withHma', weights: [], weightedScore: 80, floorBand: 30, floorHeldBy: [] },
  hmaData: null, credentialData: null, detectData: null,
});

const INHERITED = /\bundefined\b|\bNaN\b|native code|function/;

test('a severity named "constructor" is counted as its own severity', () => {
  const t = overviewText(report([finding('aa000001', 'constructor', 'hma')], ['aa000001']));
  assert.match(t, /No critical or high findings\. 1 constructor finding to review\./);
  assert.match(t, /critical 0 high 0 medium 0 low 0 constructor 1/);
  assert.doesNotMatch(t, INHERITED);
});

test('a source named "constructor" is printed as itself and is not given a tab', () => {
  const t = overviewText(report([finding('aa000001', 'high', 'hma'), finding('aa000002', 'low', 'constructor')], ['aa000001']));
  // Score 80 and no critical: the terminal Verdict's "Good overall" (#552).
  assert.match(t, /Good overall: 1 high and 1 low findings to harden\./);
  assert.match(t, /1 more finding: ?$/);
  assert.doesNotMatch(t, INHERITED);
  const own = overviewText(report([finding('aa000002', 'low', 'constructor')], ['aa000002']));
  assert.match(own, /Found by constructor X-1/);
  assert.doesNotMatch(own, INHERITED);
});

test('a Fix first entry named "constructor" with no finding behind it shows no card', () => {
  const html = overviewHtml(report([finding('aa000001', 'high', 'hma')], ['aa000001', 'constructor']));
  assert.deepEqual(html.match(/<article class="ff-card"[^>]*>/g), ['<article class="ff-card" id="ff-aa000001" aria-labelledby="ff-title-1">']);
});
