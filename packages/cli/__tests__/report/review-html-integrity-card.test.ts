// The Shield tab's Integrity card in the review HTML prints the integrity
// status the report carries, and never a status the report does not carry.
//
// The card read `shield.integrityStatus || 'healthy'`, so a report whose
// Shield data held no integrity status showed "healthy" in red: a pass
// word nothing had measured. A missing status now reads "Not checked" in the
// muted colour.
//
// The pages are rendered client-side, so this test runs the report's own
// client script against a minimal DOM and reads the Shield page.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { generateReviewHtml } from '../../src/report/review-html.js';
import type { ReviewReport } from '../../src/commands/review.js';

const SRC = join(__dirname, '..', '..', 'src');

/** Run the report's client script and return the Shield page's HTML. */
function renderShieldPage(report: ReviewReport): string {
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
  navClick!({ target: { closest: () => ({ getAttribute: () => 'shield' }) } });
  return pages['page-shield']?.innerHTML ?? '';
}

function report(integrityStatus: unknown, omit = false): ReviewReport {
  const shieldData: Record<string, unknown> = {
    eventCount: 0,
    classifiedFindings: [],
    arpStats: {
      totalEvents: 0, anomalies: 0, violations: 0, threats: 0,
      processEvents: 0, networkEvents: 0, filesystemEvents: 0, enforcements: 0,
    },
    chainBroken: false,
    untrustedEventsExcluded: 0,
    brokenAt: null,
    shieldPostureScore: 60,
    policyLoaded: false,
    policyMode: null,
    integrityStatus,
  };
  if (omit) delete shieldData.integrityStatus;
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
    credentialData: { totalFindings: 0, bySeverity: {}, matches: [], driftFindings: [] } as never,
    guardData: { filesMonitored: 0, tamperedFiles: [], signatureStatus: 'unsigned' } as never,
    shieldData: shieldData as never,
    hmaData: null,
    detectData: {
      governanceScore: 50, agents: [], mcpServers: [], aiConfigs: [],
      identity: { aimIdentities: 0, mcpIdentities: 0, soulFiles: 0, capabilityPolicies: 0 },
      findings: [],
      recoverablePoints: 0,
    },
  } as ReviewReport;
}

/** The Integrity stat card's value and colour. */
function integrityCard(page: string): { value: string; color: string } {
  const m = /<div class="stat-value" style="color:([^"]*)">([^<]*)<\/div><div class="stat-label">Integrity<\/div>/.exec(page);
  expect(m, 'the Integrity card is on the Shield page').not.toBeNull();
  return { color: m![1], value: m![2] };
}

describe('review HTML Integrity card', () => {
  it('prints no status when the report carries none', () => {
    for (const r of [report(undefined, true), report(undefined), report(null), report('')]) {
      const card = integrityCard(renderShieldPage(r));
      expect(card.value).not.toMatch(/healthy|pass|verified|ok/i);
      expect(card.value).toBe('Not checked');
      expect(card.color).toBe('var(--muted)');
    }
  });

  it('prints a status the report carries as carried', () => {
    expect(integrityCard(renderShieldPage(report('healthy')))).toEqual({ value: 'healthy', color: 'var(--green)' });
    for (const status of ['degraded', 'compromised', 'lockdown']) {
      expect(integrityCard(renderShieldPage(report(status)))).toEqual({ value: status, color: 'var(--red)' });
    }
  });

  it('no source in the CLI or its UI package defaults a missing value to a pass word', () => {
    const roots = [SRC, join(__dirname, '..', '..', '..', 'cli-ui', 'src')];
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name);
        if (statSync(p).isDirectory()) { if (name !== '__tests__') walk(p); }
        else if (/\.(ts|tsx|js|mjs)$/.test(name) && !/\.test\./.test(name)) files.push(p);
      }
    };
    roots.forEach(walk);
    expect(files.length, 'the sweep reads source files').toBeGreaterThan(10);
    const sites = files.flatMap(f => readFileSync(f, 'utf-8').split('\n').flatMap((line, i) =>
      [...line.matchAll(/(\|\||\?\?) *['"](healthy|pass|passed|safe|clean|ok|valid|intact|secure|verified|trusted)['"]/g)]
        .map(m => `${f.slice(SRC.length - 'cli/src'.length)}:${i + 1}: ${m[0]}`)));
    expect(sites).toEqual([]);
  });
});
