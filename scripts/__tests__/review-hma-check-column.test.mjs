/**
 * The check ID in the HMA tab's "Issues by Check" table of the review report
 * wraps inside its own column (issue #410).
 *
 * Below 900px the table keeps a 640px minimum width and the Check column is
 * 14% of it, about 70px for the ID once the cell padding is taken off. The
 * Check cell was set to white-space:nowrap, so at 375px an ID such as
 * SKILL-MEM-003 ran out of its fixed-layout cell and over the cells beside it.
 * The cell now wraps like every other cell in the table: the stylesheet breaks
 * a word that does not fit, which for a check ID falls at its hyphens.
 *
 * The tab is rendered in the browser from the report JSON, so this test runs
 * the report's own client script against a minimal DOM and reads the rows it
 * writes. Loads the built CLI module (`packages/cli/dist`), so `npm run build`
 * comes first. No file is written and no process is started.
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
const { generateReviewHtml } = require(path.join(DIST, 'review-html.js'));

const FILES = Array.from({ length: 12 }, (_, i) => `skills/memory/handler-${i}.md:${i + 1}`);
const FINDINGS = [
  { checkId: 'SKILL-MEM-003', name: 'Skill writes agent memory', description: 'd', category: 'skill',
    severity: 'critical', count: 12, fix: 'hackmyagent secure --fix', sampleFiles: FILES },
  { checkId: 'CRED-001', name: 'Credential in source', description: 'd', category: 'credentials',
    severity: 'high', count: 1, fix: 'npx secretless-ai init', sampleFiles: [FILES[0]] },
];

const html = generateReviewHtml({
  timestamp: '2026-10-06T00:00:00Z', directory: '/tmp/x', projectName: 't', projectType: 'node',
  phases: [], compositeScore: 50, provisional: false, grade: 'C',
  recoverySummary: { totalRecoverable: 0, opportunities: [], potentialScore: 100 },
  findings: [], actionItems: [],
  hmaData: {
    available: true, score: 60, maxScore: 100, totalChecks: 100, passed: 98, failed: 2,
    bySeverity: { critical: 1, high: 1 }, byCategory: { skill: 1, credentials: 1 },
    topFindings: FINDINGS, allFailedFindings: FINDINGS,
  },
});

/** The HTML the report's client script writes for the HMA tab. */
function renderHmaPage() {
  const data = /<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/.exec(html)[1];
  const script = /<script>\n([\s\S]*?)<\/script>/.exec(html)[1];
  const pages = {};
  let navClick;
  const document = {
    getElementById(id) {
      if (id === 'report-data') return { textContent: data };
      if (id === 'main-nav') return { addEventListener: (_t, fn) => { navClick = fn; } };
      return (pages[id] ??= { innerHTML: '', querySelectorAll: () => [] });
    },
    querySelectorAll: () => [],
    querySelector: () => null,
  };
  runInNewContext(script, { document, window: { addEventListener: () => {} }, navigator: {}, setTimeout });
  assert.equal(typeof navClick, 'function', 'the nav handler was registered');
  navClick({ target: { closest: () => ({ getAttribute: () => 'hma' }) } });
  return pages['page-hma'].innerHTML;
}

/** The stylesheet with comments and formatting whitespace removed. */
const css = html
  .slice(html.indexOf('<style>'), html.indexOf('</style>'))
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/\s+/g, ' ')
  .replace(/\s*([{};:,>])\s*/g, '$1');

test('each HMA check ID sits in a Check cell that may wrap', () => {
  const page = renderHmaPage();
  const table = page.slice(page.indexOf('<table class="data-table hma-table">'), page.indexOf('</table>'));
  const rows = [...table.matchAll(/<tr\b[^>]*>(<td\b[^>]*>)([^<]*)<\/td>/g)];
  // Non-vacuity: one row per finding, each opening with its check ID.
  assert.deepEqual(rows.map(r => r[2]), FINDINGS.map(f => f.checkId));
  for (const [, cell, id] of rows) {
    assert.doesNotMatch(cell, /nowrap|white-space/, `the Check cell of ${id} keeps the ID on one line: ${cell}`);
  }
  // The "+ N more" toggle the long ID ran towards is in the same row.
  assert.match(table, /<button type="button" class="expand-toggle" aria-expanded="false" onclick="toggleExpand\(this\)">\+ 9 more<\/button>/);
});

test('the HMA table breaks a word that does not fit its fixed-width cell', () => {
  const rule = /\.data-table\.hma-table th,\.data-table\.hma-table td\{([^}]*)\}/.exec(css);
  assert.ok(rule, 'the HMA table cell rule is in the stylesheet');
  assert.match(rule[1], /overflow-wrap:break-word/);
  assert.match(/\.data-table\.hma-table\{([^}]*)\}/.exec(css)?.[1] ?? '', /table-layout:fixed/);
});
