// Every Copy control on the pages this test renders holds a command that runs
// as pasted and changes nothing irreversibly.
//
// The Copy button puts its text on the clipboard with one click. Three shapes
// must not sit behind it:
//   - a `<...>` placeholder (`hackmyagent check <skill-path>`, `opena2a shield
//     evaluate --action process.spawn --target <binary>`). Pasted, the shell
//     reads `<binary>` as a file redirection and stops with a syntax error.
//   - a step that rewrites history or deletes data (`git filter-repo`, `rm`)
//     behind the same single click as a read-only check. A scan's fix text is
//     free text, so such a step can arrive from a scanner.
//   - a chain that cannot reach its second step (`opena2a guard diff &&
//     opena2a guard resign`: `guard diff` exits 1 whenever a file changed,
//     which is the only case the step is shown for), and prose such as
//     "Run daemon as non-root user" offered as if it were a command.
//
// The pages are rendered client-side, so this test runs the report's own
// client script against a minimal DOM and reads every Copy control on every
// page. The rules below are written independently of the renderer's.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runInNewContext } from 'node:vm';
import { generateReviewHtml } from '../../src/report/review-html.js';
import { assembleReviewClientScript } from '../../src/report/review-assets.js';
import type { ReviewReport } from '../../src/commands/review.js';
import { FINDING_CATALOG } from '../../src/shield/findings.js';
import { ADAPTER_REGISTRY } from '../../src/adapters/registry.js';

const SRC = join(__dirname, '..', '..', 'src');
const CLIENT_SRC = assembleReviewClientScript();
const REVIEW_SRC = readFileSync(join(SRC, 'commands', 'review.ts'), 'utf-8');
const INDEX_SRC = readFileSync(join(SRC, 'index.ts'), 'utf-8');

const PAGES = ['overview', 'credentials', 'hygiene', 'shield', 'hma', 'shadowai'] as const;

/** Run the report's client script and return the HTML of every page. */
function renderPages(report: ReviewReport): Record<string, string> {
  const html = generateReviewHtml(report);
  const data = /<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/.exec(html)![1];
  const script = /<script>\n([\s\S]*?)<\/script>/.exec(html)![1];

  const pages: Record<string, { innerHTML: string; querySelectorAll: () => never[] }> = {};
  let navClick: ((e: unknown) => void) | undefined;
  const document = {
    getElementById(id: string) {
      if (id === 'report-data') return { textContent: data };
      if (id === 'main-nav') return { addEventListener: (_t: string, fn: (e: unknown) => void) => { navClick = fn; } };
      return (pages[id] ??= { innerHTML: '', querySelectorAll: () => [] });
    },
    querySelectorAll: () => [],
    querySelector: () => null,
  };
  runInNewContext(script, { document, window: { addEventListener: () => {} }, navigator: {}, setTimeout });
  expect(navClick, 'the nav handler was registered').toBeTypeOf('function');
  for (const page of PAGES) {
    navClick!({ target: { closest: () => ({ getAttribute: () => page }) } });
  }
  return Object.fromEntries(PAGES.map(p => [p, pages[`page-${p}`]?.innerHTML ?? '']));
}

function decode(s: string): string {
  return s.replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
}

/** The text each Copy control puts on the clipboard. */
function copyTexts(pageHtml: string): string[] {
  return [...pageHtml.matchAll(/<button [^>]*class="copy-btn"[^>]*data-cmd="([^"]*)"/g)].map(m => decode(m[1]));
}

/** Commands shown without a Copy control, with the note shown under them. */
function withheld(pageHtml: string): { cmd: string; note: string }[] {
  return [...pageHtml.matchAll(
    /<div class="cmd-block cmd-manual"><span class="cmd-text">([^<]*)<\/span><\/div><div class="cmd-note">([^<]*)<\/div>/g,
  )].map(m => ({ cmd: decode(m[1]), note: decode(m[2]) }));
}

const COPY_EXECUTABLES = new Set(['opena2a', 'hackmyagent', 'npx', 'npm', 'git', 'gh', 'echo']);

/** Top-level command names and aliases the program registers. */
const REGISTERED = new Set<string>([
  ...[...INDEX_SRC.matchAll(/\.command\('([a-z][a-z-]*)/g)].map(m => m[1]),
  ...[...INDEX_SRC.matchAll(/\.alias\('([a-z][a-z-]*)'\)/g)].map(m => m[1]),
  ...Object.entries(ADAPTER_REGISTRY).flatMap(([name, c]) => [name, ...(c.aliases ?? [])]),
]);

/** Why a command must not sit behind a Copy control, or null when it may. */
function whyNotCopyable(cmd: string): string | null {
  if (!cmd.trim()) return 'empty';
  const ph = /<[A-Za-z][\w.:-]*>/.exec(cmd);
  if (ph) return `placeholder ${ph[0]}`;
  const segments = cmd.split(/\s*(?:&&|\|\||;|\|)\s*/).map(s => s.trim()).filter(Boolean);
  for (const seg of segments) {
    const t = seg.split(/\s+/);
    if (t[0] === 'rm' || t[0] === 'bfg' || t[0] === 'shred') return `destructive: ${seg}`;
    if (t[0] === 'git' && /^filter-(repo|branch)$/.test(t[1] ?? '')) return `history rewrite: ${seg}`;
    if (t[0] === 'git' && t[1] === 'reset' && t.includes('--hard')) return `destructive: ${seg}`;
    if (!COPY_EXECUTABLES.has(t[0])) return `not a command: ${seg}`;
    if (t[0] === 'opena2a' && !REGISTERED.has(t[1])) return `unregistered: ${seg}`;
  }
  // `guard diff` exits 1 on any change, so nothing chained after it runs.
  if (/opena2a guard diff\s*&&/.test(cmd)) return 'dead-end chain after guard diff';
  return null;
}

/**
 * Catalog remediations whose wording is being rewritten separately, together
 * with the finding they belong to. Each still holds a chain after a command
 * that exits non-zero on the finding's own condition. Remove an entry when
 * its catalog text changes.
 */
const PENDING_CATALOG_REWRITE = new Set([
  FINDING_CATALOG['SHIELD-INT-001'].remediation,
].filter(r => /&&/.test(r)));

/** Every single-quoted `<field>: '...'` literal in review.ts. */
function literals(field: string): string[] {
  return [...REVIEW_SRC.matchAll(new RegExp(`\\b${field}: '([^']+)'`, 'g'))].map(m => m[1]);
}

/** The argument text of every `name(` call in `src`, balanced on parentheses. */
function callArguments(src: string, name: string): string[] {
  const out: string[] = [];
  for (let at = src.indexOf(name); at >= 0; at = src.indexOf(name, at + 1)) {
    let depth = 1;
    let i = at + name.length;
    for (; i < src.length && depth > 0; i++) {
      if (src[i] === '(') depth++;
      else if (src[i] === ')') depth--;
    }
    out.push(src.slice(at + name.length, i - 1));
  }
  return out;
}

const HMA_FINDINGS = [
  { checkId: 'SKILL-001', name: 'n', description: 'd', category: 'skill', severity: 'high', count: 1,
    fix: 'Remove the shell call', sampleFiles: ["skills/it's & more.md:3"] },
  { checkId: 'SKILL-002', name: 'n', description: 'd', category: 'skill', severity: 'high', count: 1,
    fix: 'Pin the skill', sampleFiles: ['-rf.md'] },
  { checkId: 'SKILL-003', name: 'n', description: 'd', category: 'skill', severity: 'high', count: 1,
    fix: 'Pin the skill' },
  { checkId: 'NEMO-001', name: 'n', description: 'd', category: 'runtime', severity: 'high', count: 1,
    fix: 'Run daemon as non-root user with minimal privileges' },
  { checkId: 'CRED-001', name: 'n', description: 'd', category: 'credentials', severity: 'high', count: 1,
    fix: 'npx secretless-ai init' },
];

function baseReport(): ReviewReport {
  const catalog = Object.values(FINDING_CATALOG);
  return {
    timestamp: '2026-10-06T00:00:00Z',
    directory: '/tmp/x',
    projectName: 't',
    projectType: 'node',
    phases: [],
    compositeScore: 50,
    provisional: false,
    grade: 'C',
    recoverySummary: { totalRecoverable: 0, opportunities: [], potentialScore: 100 },
    findings: [],
    actionItems: [],
    initData: {
      trustScore: 80, postureScore: 75, riskLevel: 'LOW', activeTools: 1, totalTools: 5,
      hygieneChecks: [], advisoryCount: 0, projectName: 't', projectType: 'node',
      projectVersion: '1.0', matchedPackages: [],
    } as never,
    credentialData: {
      totalFindings: 1, bySeverity: { critical: 1 }, matches: [], driftFindings: [],
    } as never,
    guardData: { filesMonitored: 2, tamperedFiles: ['mcp.json'], signatureStatus: 'tampered' } as never,
    shieldData: {
      eventCount: 3,
      // Every Shield finding, so each catalog remediation reaches the page.
      classifiedFindings: catalog.map(finding => ({ finding, count: 1, firstSeen: '', lastSeen: '', examples: [] })),
      arpStats: {
        totalEvents: 0, anomalies: 0, violations: 0, threats: 0,
        processEvents: 0, networkEvents: 0, filesystemEvents: 0, enforcements: 0,
      },
      chainBroken: true,
      untrustedEventsExcluded: 1,
      brokenAt: 2,
      shieldPostureScore: 60,
      policyLoaded: false,
      policyMode: null,
      integrityStatus: 'degraded',
    } as never,
    hmaData: {
      available: true, score: 60, maxScore: 100, totalChecks: 100, passed: 96, failed: 4,
      bySeverity: { high: 4 }, byCategory: { skill: 3, runtime: 1 },
      topFindings: HMA_FINDINGS,
      allFailedFindings: HMA_FINDINGS,
    } as never,
    detectData: {
      governanceScore: 50, agents: [], mcpServers: [], aiConfigs: [],
      identity: { aimIdentities: 0, mcpIdentities: 0, soulFiles: 0, capabilityPolicies: 0 },
      // Every remediation review.ts can emit.
      findings: literals('remediation').map((remediation, i) => ({
        severity: 'high', title: `finding ${i}`, whyItMatters: 'w', remediation,
      })),
      recoverablePoints: 0,
    },
  } as ReviewReport;
}

function renderAll(): Record<string, string>[] {
  const tampered = baseReport();
  const unsignedNoHma = baseReport();
  unsignedNoHma.guardData = { filesMonitored: 0, tamperedFiles: [], signatureStatus: 'unsigned' } as never;
  unsignedNoHma.hmaData = null;
  // A credential check that read no file, so the Credentials page asks for a rerun.
  unsignedNoHma.credentialData = {
    totalFindings: 0, filesScanned: 0, bySeverity: {}, matches: [], driftFindings: [],
  } as never;
  return [renderPages(tampered), renderPages(unsignedNoHma)];
}

describe('review HTML Copy controls', () => {
  const renders = renderAll();
  const allCopies = renders.flatMap(r => PAGES.flatMap(p => copyTexts(r[p])));
  const allWithheld = renders.flatMap(r => PAGES.flatMap(p => withheld(r[p])));

  it('renders Copy controls at all (guards the harness)', () => {
    expect(allCopies).toContain('opena2a protect');
    expect(allCopies).toContain('opena2a shield selfcheck');
    expect(allCopies).toContain('npm install -g hackmyagent');
    expect(allCopies).toContain('opena2a guard sign');
    expect(literals('remediation').length).toBeGreaterThan(3);
    expect(REGISTERED.has('harden-soul')).toBe(true);
    expect(REGISTERED.has('not-a-command')).toBe(false);
  });

  it('every Copy control holds a runnable, non-destructive command', () => {
    const bad = allCopies
      .filter(c => !PENDING_CATALOG_REWRITE.has(c))
      .map(c => [c, whyNotCopyable(c)])
      .filter(([, why]) => why);
    expect(bad).toEqual([]);
  });

  it('a placeholder is shown without a Copy control, with what to replace', () => {
    const withPlaceholder = Object.values(FINDING_CATALOG)
      .map(f => f.remediation)
      .filter(r => /<[\w-]+>/.test(r) && !/filter-repo/.test(r));
    expect(withPlaceholder.length).toBeGreaterThan(0);
    for (const cmd of ['hackmyagent check <skill-path>', ...withPlaceholder]) {
      const w = allWithheld.find(x => x.cmd === cmd);
      expect(w, `"${cmd}" is still on the page`).toBeDefined();
      expect(w!.note).toMatch(/replace <[\w-]+>/);
    }
  });

  it('a history rewrite is shown in words without a Copy control', () => {
    const rewrites = Object.values(FINDING_CATALOG).map(f => f.remediation).filter(r => /filter-repo/.test(r));
    for (const cmd of rewrites) {
      const w = allWithheld.find(x => x.cmd === cmd);
      expect(w, `"${cmd}" is still on the page`).toBeDefined();
      expect(w!.note).toMatch(/cannot be undone/);
      expect(w!.note).toMatch(/only after you have read it/);
    }
    expect(allCopies.some(c => /filter-repo/.test(c))).toBe(false);
  });

  it('tampered config offers guard diff and guard resign as two steps', () => {
    const hygiene = copyTexts(renders[0].hygiene);
    expect(hygiene).toContain('opena2a guard diff');
    expect(hygiene).toContain('opena2a guard resign');
    expect(renders[0].hygiene).toContain('mcp.json');
    // `guard sign` rewrites the signature store without a prompt, so offering
    // it for a tampered project would replace the evidence of the change.
    expect(hygiene).not.toContain('opena2a guard sign');
    expect(renders[0].hygiene).not.toContain('Not active');
    expect(copyTexts(renders[1].hygiene)).toContain('opena2a guard sign');
  });

  it('every action command in the JSON report runs as written', () => {
    // The JSON report's action items carry a bare `command`; a script that
    // reads one runs it as is.
    const bad = literals('command').map(c => [c, whyNotCopyable(c)]).filter(([, why]) => why);
    expect(bad).toEqual([]);
  });

  it('prose fix text is not offered as a command', () => {
    expect(allCopies).not.toContain('Run daemon as non-root user with minimal privileges');
    expect(renders[0].hma).toContain('Run daemon as non-root user with minimal privileges');
  });

  it('a skill path is quoted so the copied command receives it as one argument', () => {
    const checks = allCopies.filter(c => c.startsWith('hackmyagent check '));
    expect(checks).toContain(`hackmyagent check 'skills/it'"'"'s & more.md'`);
    expect(checks).toContain('hackmyagent check ./-rf.md');
    for (const [cmd, want] of [
      [`hackmyagent check 'skills/it'"'"'s & more.md'`, "skills/it's & more.md"],
      ['hackmyagent check ./-rf.md', './-rf.md'],
    ]) {
      const argv = cmd.replace(/^hackmyagent check /, '');
      const res = spawnSync('/bin/sh', ['-c', `printf '%s' ${argv}`], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
      expect(res.status).toBe(0);
      expect(res.stdout).toBe(want);
    }
  });

  it('walks every cmdBlock call site in the renderer', () => {
    // A new call site is a visible diff here: add it, and add a fixture above
    // that reaches it, so its Copy text is checked.
    const sites = callArguments(CLIENT_SRC, 'cmdBlock(').filter(arg => arg !== 'cmd');
    expect(sites).toEqual([
      "'opena2a review .'",
      "'opena2a protect'",
      "'opena2a guard diff'",
      "'opena2a guard resign'",
      "'opena2a guard sign'",
      "'opena2a shield selfcheck'",
      'f.finding.remediation',
      "'opena2a runtime start'",
      "'opena2a shield init'",
      "'npm install -g hackmyagent'",
      'f.fix',
      "'hackmyagent check ' + (f.sampleFiles && f.sampleFiles[0] ? shellArg(f.sampleFiles[0].split(':')[0]) : '<skill-path>')",
      "'npx secretless-ai init'",
      "'hackmyagent check <skill-path>'",
      "'hackmyagent secure --fix'",
      "'opena2a runtime start'",
      'f.remediation',
    ]);
    for (const arg of sites.filter(a => /^'[^']*'$/.test(a))) {
      const cmd = arg.slice(1, -1);
      const shown = allCopies.includes(cmd) || allWithheld.some(w => w.cmd === cmd);
      expect(shown, `literal ${arg} reached a rendered page`).toBe(true);
    }
  });
});
