// The Findings tab lists every analyzer's results once, replacing the HMA,
// Credentials and Shield tabs, where the Credentials tab said "Your project is
// clean." beside HMA's critical secrets in the same files. The client script
// runs here against a stub document.

import { describe, it, expect } from 'vitest';
import { runInNewContext } from 'node:vm';
import { assembleReviewClientScript } from '../../src/report/review-assets.js';

type Stub = Record<string, any>;

/** Runs the client script against stub nodes; `open(tab)` renders a tab and returns its markup. */
function load(report: object, hash = '', preset: Record<string, Stub> = {}) {
  const nodes: Record<string, Stub> = { ...preset };
  let onNav: (e: Stub) => void = () => {};
  const node = (id: string): Stub => (nodes[id] ??= { innerHTML: '', querySelectorAll: () => [] });
  const navTo = (page: string) => onNav({ target: { closest: () => ({ getAttribute: () => page }) } });
  const document = {
    getElementById: (id: string) => {
      if (id === 'report-data') return { textContent: JSON.stringify(report) };
      if (id === 'main-nav') return { addEventListener: (_: string, fn: typeof onNav) => { onNav = fn; } };
      return node(id);
    },
    querySelectorAll: () => [],
    querySelector: (sel: string) => ({ click: () => navTo(/data-page="(\w+)"/.exec(sel)![1]), focus() {} }),
  };
  const window: Stub = { addEventListener() {}, location: { hash } };
  runInNewContext(assembleReviewClientScript(), { document, window });
  return { window, open: (tab: string) => { navTo(tab); return node('page-' + tab).innerHTML; } };
}

function text(html: string): string {
  return html.replace(/<[^>]+>/g, ' ').replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&#39;/g, "'").replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
}

const finding = (n: number) => ({
  fingerprint: n.toString(16).padStart(8, '0'),
  title: `Check ${n} failed (src/file-${n}.js)`,
  severity: ['critical', 'high', 'medium', 'low'][n % 4],
  confidence: null,
  category: 'Supply chain',
  foundBy: [{ source: 'hma', checkId: `CHK-${n}`, lines: [] }],
  locations: [{ file: `src/file-${n}.js`, line: n }],
  evidence: [], reason: null, fix: null, then: null, advice: null,
  verify: { command: 'opena2a secure', tool: 'opena2a', expect: `CHK-${n} is not reported` },
  recovery: { kind: 'nextRun', points: null, from: 0, to: null },
  occurrences: 1,
});

// The merged .env exposure measured on the envcase tree.
const ENV_GROUP = {
  ...finding(0),
  fingerprint: '6305afb6',
  title: '.env is not ignored by git and sets 3 values',
  severity: 'critical',
  confidence: 'confirmed',
  category: 'Secrets',
  foundBy: [
    { source: 'hygiene', checkId: '.env protection', lines: [] },
    { source: 'hma', checkId: 'GIT-003', lines: [] },
    { source: 'hma', checkId: 'SEM-CRED-002', lines: [2, 3] },
  ],
  locations: [{ file: '.env', line: null }],
  evidence: [{ file: '.gitignore', line: null, text: 'no rule matches .env' }],
  reason: 'No .gitignore rule matches .env, so `git add .` stages it.',
  fix: { command: "printf '\\n.env\\n' >> .gitignore", tool: 'shell', changes: 'Appends one ignore rule to .gitignore.' },
  verify: { command: 'git check-ignore -v -- .env', tool: 'git', expect: '.gitignore:<line>:.env  .env' },
  recovery: { kind: 'atLeast', points: 3, from: 88, to: 91 },
  occurrences: 4,
};

const report = (findings: Stub[], o: Stub = {}) => ({
  directory: '/tmp/demo', compositeScore: 0, provisional: false, phases: [],
  reportFindings: findings, fixFirst: findings.slice(0, 3).map(f => f.fingerprint),
  scoreModel: { floorHeldBy: [], floorBand: 30 }, credentialData: { filesScanned: 28 },
  hmaData: { available: true, totalChecks: 165 }, detectData: { mcpServers: [], aiConfigs: [] }, ...o,
});

describe('review report: Findings', () => {
  it('lists every finding once, in report order, as a collapsed native disclosure with its own anchor', () => {
    const many = Array.from({ length: 114 }, (_, i) => finding(i + 1)); // HMA's failed count on test/hma
    const html = load(report(many)).open('findings');
    expect([...html.matchAll(/<details class="fd" id="f-([0-9a-f]{8})">/g)].map(m => m[1])).toEqual(many.map(f => f.fingerprint));
    expect(text(html)).toContain('Findings (114)');
    expect(html).not.toMatch(/<details[^>]* open/);
  });

  it('shows a merged finding with every check that contributed, its evidence, fix, verify and recovery', () => {
    const t = text(load(report([ENV_GROUP, finding(1)])).open('findings'));
    expect(t).toContain('critical confirmed .env is not ignored by git and sets 3 values at least +3');
    expect(t).toContain('Found by hygiene ".env protection" · HMA GIT-003 · HMA SEM-CRED-002 (lines 2, 3)');
    expect(t).toContain('Evidence .gitignore no rule matches .env');
    expect(t).toContain("Fix printf '\\n.env\\n' >> .gitignore shell Copy");
    expect(t).toContain('Verify git check-ignore -v -- .env git Copy Expect: .gitignore:<line>:.env .env');
    expect(t).toContain('Recovery at least +3 (88 -> 91 re-scored; the rest is measured on the next run)');
    expect(t).toContain('Link #f-6305afb6');
  });

  it('a #f-<fingerprint> URL opens the Findings tab, opens that finding and scrolls to it', () => {
    const target: Stub = { open: false, scrolled: 0 };
    target.scrollIntoView = () => { target.scrolled++; };
    target.querySelector = () => ({ focus() { target.focused = true; } });
    const page = load(report([ENV_GROUP]), '#f-6305afb6', { 'f-6305afb6': target });
    expect(target).toMatchObject({ open: true, scrolled: 1, focused: true });
    target.open = false;
    page.window.openFinding('6305afb6'); // the same link, followed again
    expect(target).toMatchObject({ open: true, scrolled: 2 });
  });

  it('says what was checked when there are no findings', () => {
    const t = text(load(report([], { phases: [{ name: 'HMA Scan', status: 'pass', durationMs: 4200 }] })).open('findings'));
    expect(t).toContain('No findings. Checked: 1 analyzer in 4.2 s. HMA ran 165 checks. 28 files read for credentials.');
  });
});

describe('review report: no all-clear beside a secret', () => {
  it('no tab claims "clean" while a Secrets finding exists', () => {
    const page = load(report([ENV_GROUP], {
      initData: { trustScore: 70, postureScore: 40, riskLevel: 'MEDIUM', activeTools: 0, totalTools: 6, hygieneChecks: [{ label: 'Credential scan', status: 'pass', detail: 'no findings' }] },
    }));
    const all = ['overview', 'findings', 'hygiene'].map(tab => text(page.open(tab))).join(' ');
    expect(all).toContain('.env is not ignored by git'); // non-vacuity: the Secrets finding is on the page
    expect(all).toContain('Hygiene Checks'); // non-vacuity: the Hygiene tab rendered
    expect(all).not.toMatch(/\bclean\b|no hardcoded credentials|Credential scan/i);
  });
});
