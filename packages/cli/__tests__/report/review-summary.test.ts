// The report opens on Summary and Fix first: the verdict, the score with only
// the recovery that was re-scored, what was checked, then at most three
// findings, each with its fix, verify and the checks that found it.
//
// Before, the first screen was a score banner, phase cards and a hardcoded
// Score Breakdown (its Shield row printed "undefined/100" and it carried a
// letter-grade legend), then Action Items whose second line was a lookup by
// severity ("Significant security gap that attackers can exploit"). A run
// without HMA showed a higher score with no word that it was provisional.
//
// The client script is run here as the page runs it, against a stub document,
// and the Overview it renders is checked as text.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { REVIEW_ASSETS_DIR, assembleReviewClientScript } from '../../src/report/review-assets.js';

/** The Overview's markup, rendered by the report's own client script. */
function renderOverview(report: object): string {
  const pages: Record<string, { innerHTML: string; querySelectorAll: () => never[] }> = {};
  const document = {
    getElementById(id: string) {
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
function text(html: string): string {
  return html.replace(/<[^>]+>/g, ' ').replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&#39;/g, "'").replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
}

const PHASES = ['Project Scan', 'Credentials', 'Config Integrity', 'Shield Analysis', 'HMA Scan', 'Shadow AI']
  .map(name => ({ name, status: 'pass', score: 90, durationMs: 700, detail: '' }));

// Values from a review of a tree whose .env git would stage (3 values; HMA ran).
const ENV_GROUP = {
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
  then: { command: 'opena2a protect --dry-run', tool: 'opena2a', changes: 'Lists the credentials protect would move into the vault; changes nothing.' },
  verify: { command: 'git check-ignore -v -- .env', tool: 'git', expect: '.gitignore:<line>:.env  .env' },
  advice: null,
  recovery: { kind: 'atLeast', points: 3, from: 88, to: 91 },
  occurrences: 4,
};
const URL_PASSWORD = {
  ...ENV_GROUP,
  fingerprint: 'd8aa4484',
  title: 'Password embedded in URL (.env:1)',
  severity: 'high',
  confidence: null,
  foundBy: [{ source: 'hma', checkId: 'SEM-CRED-001', lines: [1] }],
  locations: [{ file: '.env', line: 1 }],
  evidence: [{ file: '.env', line: 1, text: 'DATABASE_URL=postgres://app:••••@localhost:5432/app' }],
  reason: 'URL-embedded credentials are logged by proxies, shell history, and process listings.',
  fix: { command: 'opena2a protect .', tool: 'opena2a', changes: null },
  then: null,
  verify: { command: 'opena2a secure', tool: 'opena2a', expect: 'SEM-CRED-001 is not reported for .env' },
  recovery: { kind: 'nextRun', points: null, from: 88, to: null },
  occurrences: 1,
};
const FILE_MODE = {
  ...URL_PASSWORD,
  fingerprint: 'b360cd16',
  title: 'Sensitive File Permissions (.env)',
  category: 'Configuration',
  foundBy: [{ source: 'hma', checkId: 'PERM-001', lines: [] }],
  evidence: [],
  reason: '.env has mode -rw-r--r--, so every user on this machine can read it.',
  fix: { command: 'chmod 600 .env', tool: 'shell', changes: 'Leaves read and write access to the owner only.' },
  verify: { command: 'ls -l .env', tool: 'shell', expect: 'the line starts with -rw-------' },
};
const LOCK_FILE = {
  ...FILE_MODE,
  fingerprint: '0b7c1e2a',
  title: 'No dependency lock file',
  severity: 'low',
  confidence: 'confirmed',
  foundBy: [{ source: 'hygiene', checkId: 'Lock file', lines: [] }],
  recovery: { kind: 'computed', points: 1, from: 88, to: 89 },
};

function report(overrides: Record<string, unknown> = {}) {
  return {
    projectName: 'envcase',
    directory: '/tmp/envcase',
    timestamp: '2026-10-08T00:00:00Z',
    compositeScore: 88,
    provisional: false,
    phases: PHASES,
    reportFindings: [ENV_GROUP, URL_PASSWORD, FILE_MODE, LOCK_FILE],
    fixFirst: ['6305afb6', 'd8aa4484', 'b360cd16'],
    optionalHardening: [],
    scoreModel: { weightSet: 'withHma', weights: [], weightedScore: 88, floorBand: 30, floorHeldBy: [] },
    hmaData: { available: true, totalChecks: 51, run: { status: 'ran', reason: null, version: 'hackmyagent 0.30.0', durationMs: 700 } },
    credentialData: { filesScanned: 5 },
    detectData: { mcpServers: [], aiConfigs: [], agents: [] },
    ...overrides,
  };
}

describe('review report: Summary', () => {
  it('states the verdict, the counts, the score with its computed recovery, and what was checked', () => {
    const t = text(renderOverview(report()));
    expect(t).toContain('Not ready to ship: 1 critical and 2 high findings.');
    expect(t).toMatch(/critical 1 high 2 medium 0 low 1/i);
    expect(t).toContain('Score 88 of 100. At least +3 available from the first fix. Items 2-3 are measured on the next run; HMA does not report per-check weights.');
    expect(t).toContain('Checked: 6 analyzers in 4.2 s. HMA 0.30.0 ran 51 checks. 5 files read for credentials. No MCP servers or AI config files in this project.');
  });

  it('names why HMA did not run and labels the score provisional', () => {
    const t = text(renderOverview(report({
      provisional: true,
      compositeScore: 91,
      phases: PHASES.map(p => (p.name === 'HMA Scan' ? { ...p, status: 'skip' } : p)),
      hmaData: { available: false, totalChecks: 0, run: { status: 'skipped', reason: 'skipped by --skip-hma', version: null, durationMs: 0 } },
    })));
    expect(t).toContain('Provisional: HMA did not run (skipped by --skip-hma). HMA-only threats are not reflected in this score.');
    expect(t).toContain('Provisional score 91 of 100.');
    expect(t).toContain('Checked: 5 of 6 analyzers');
    expect(t).not.toContain('HMA 0.30.0');
  });

  it('says in words when an analyzer holds the score at the floor', () => {
    const held = { ...ENV_GROUP, recovery: { kind: 'none', points: 0, from: 0, to: 0 } };
    const t = text(renderOverview(report({
      compositeScore: 0,
      reportFindings: [held],
      fixFirst: [held.fingerprint],
      scoreModel: { weightSet: 'withHma', weights: [], weightedScore: 72, floorBand: 30, floorHeldBy: ['HMA Scan'] },
    })));
    expect(t).toContain('Score 0 of 100. The score is held at 0 because HMA scored this tree 0 of 100. It rises once that score reaches 30; fixes in other areas do not change the score until then.');
    expect(t).toContain('no score change');
    expect(t).not.toMatch(/available from the first fix/);
  });

  it('counts only the MCP servers declared in this project, not ones configured on this machine', () => {
    const t = text(renderOverview(report({
      detectData: {
        mcpServers: [
          { name: 'files', source: '.mcp.json (project)' },
          { name: 'browser', source: 'Claude Desktop' },
        ],
        aiConfigs: [],
        agents: [{ name: 'Claude Code' }],
      },
    })));
    expect(t).toContain('In this project: 1 MCP server, 0 AI config files.');
  });

  it('claims nothing it did not measure when there are no findings', () => {
    const html = renderOverview(report({ reportFindings: [], fixFirst: [] }));
    const t = text(html);
    expect(t).toContain('No findings.');
    expect(t).toContain('No findings to fix.');
    expect(t).toContain('Checked: 6 analyzers');
    expect(t).not.toMatch(/\bundefined\b|\bNaN\b/);
  });
});

describe('review report: Fix first', () => {
  const html = renderOverview(report());
  const t = text(html);

  it('shows at most three cards, in the report order, each with fix, verify and the checks that found it', () => {
    const cards = html.match(/<article class="ff-card" id="ff-[0-9a-f]{8}"/g) ?? [];
    expect(cards).toEqual(['6305afb6', 'd8aa4484', 'b360cd16'].map(fp => `<article class="ff-card" id="ff-${fp}"`));
    expect(t).toContain('.env is not ignored by git and sets 3 values');
    expect(t).toContain('Found by hygiene ".env protection" · HMA GIT-003 · HMA SEM-CRED-002 (lines 2, 3)');
    expect(t).toContain('Recovery at least +3 (88 -> 91 re-scored; the rest is measured on the next run)');
    expect(t).toContain('Expect: the line starts with -rw-------');
    expect(t).not.toContain('No dependency lock file'); // the fourth finding stays out of Fix first
    expect(t).toContain('1 more finding: Hygiene 1');
  });

  it('the first command on the page is the first card\'s fix', () => {
    const first = /<div class="cmd-block"( data-fix)?><span class="cmd-text">([^<]*)<\/span>/.exec(html);
    expect(first?.[1]).toBe(' data-fix');
    expect(text(first![2])).toBe("printf '\\n.env\\n' >> .gitignore");
  });

  it('every Copy button is a labelled native button carrying its command', () => {
    const buttons = html.match(/<button[^>]*class="copy-btn"[^>]*>/g) ?? [];
    expect(buttons).toHaveLength(7); // fix, then and verify; fix and verify; fix and verify
    for (const b of buttons) {
      expect(b).toMatch(/^<button type="button" class="copy-btn" aria-label="Copy (Fix|Then|Verify) command" data-cmd="[^"]+"/);
    }
  });

  it('a reason is the finding\'s own; nothing is filled in by severity', () => {
    expect(t).toContain('URL-embedded credentials are logged by proxies');
    const noReason = renderOverview(report({ reportFindings: [{ ...FILE_MODE, reason: null }], fixFirst: [FILE_MODE.fingerprint] }));
    expect(text(noReason)).not.toContain('Why here');
  });
});

describe('review report: Summary and Fix first wording', () => {
  const src = readFileSync(join(REVIEW_ASSETS_DIR, 'client', '10-overview.js'), 'utf-8');

  it('carries no letter grade, deduction, alarm copy or blanket all-clear', () => {
    for (const banned of [/\b[A-F]<\/strong> \d+\+/, /deducted/i, /#1 cause/i, /Your project is clean/i, /path to/i, /actionImpact/, /\bgrade\b/i]) {
      expect(src).not.toMatch(banned);
    }
    expect(src).toContain('function renderOverview('); // non-vacuity: the real file
  });
});
