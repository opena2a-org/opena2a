/**
 * A finding whose behaviour no MITRE ATLAS technique describes carries
 * `mitreAtlas: null`. Before that value could appear in the catalog, every
 * place that emits it had to stop treating it as an id: SARIF wrote `null`
 * into a rule's `tags`, the HTML report's `compliance` badges threw on it,
 * the MITRE column rendered an empty badge, and the findings search text
 * carried the word "null".
 */

import { describe, it, expect } from 'vitest';
import { runInNewContext } from 'node:vm';
import { FINDING_CATALOG, frameworkTags } from '../../src/shield/findings.js';
import type { ClassifiedFinding, FindingDefinition } from '../../src/shield/findings.js';
import { toSarif } from '../../src/shield/sarif.js';
import { generateShieldHtmlReport } from '../../src/shield/report-html.js';
import type { WeeklyReport } from '../../src/shield/types.js';

function withAtlas(id: string, mitreAtlas: string | null): FindingDefinition {
  return { ...FINDING_CATALOG[id], mitreAtlas };
}

function classified(finding: FindingDefinition): ClassifiedFinding {
  return {
    finding,
    count: 2,
    firstSeen: '2026-10-01T00:00:00.000Z',
    lastSeen: '2026-10-02T00:00:00.000Z',
    examples: [],
  };
}

function minimalReport(): WeeklyReport {
  return {
    version: 1,
    generatedAt: '2026-10-06T00:00:00.000Z',
    periodStart: '2026-09-29T00:00:00.000Z',
    periodEnd: '2026-10-06T00:00:00.000Z',
    hostname: 'dev-workstation',
    agentActivity: { totalSessions: 0, totalActions: 0, byAgent: {} },
    policyEvaluation: { monitored: 0, wouldBlock: 0, blocked: 0, topViolations: [] },
    credentialExposure: { accessAttempts: 0, uniqueCredentials: 0, byProvider: {}, recommendations: [] },
    supplyChain: { packagesInstalled: 0, advisoriesFound: 0, blockedInstalls: 0, lowTrustPackages: [] },
    configIntegrity: { filesMonitored: 0, tamperedFiles: [], signatureStatus: 'valid' },
    runtimeProtection: { arpActive: false, processesSpawned: 0, networkConnections: 0, anomalies: 0 },
    posture: { score: 90, grade: 'strong', factors: [], trend: null, comparative: null },
  } as WeeklyReport;
}

/** Run the report's own script against a stub DOM; return the rendered pages. */
function renderPages(findings: ClassifiedFinding[]): { overview: string; findings: string } {
  const html = generateShieldHtmlReport(minimalReport(), null, findings);
  const script = html.slice(html.lastIndexOf('<script>') + '<script>'.length, html.lastIndexOf('</script>'));
  const payload = html.slice(
    html.indexOf('>', html.indexOf('<script id="report-data"')) + 1,
    html.indexOf('</script>'),
  );
  const nodes = new Map<string, any>();
  const handlers = new Map<string, (e: any) => void>();
  const node = (id: string) => {
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        innerHTML: '',
        classList: { toggle: () => {}, add: () => {}, remove: () => {} },
        addEventListener: (type: string, fn: (e: any) => void) => handlers.set(`${id}:${type}`, fn),
      });
    }
    return nodes.get(id);
  };
  const escapeHtml = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const documentStub = {
    getElementById: (id: string) => (id === 'report-data' ? { textContent: payload } : node(id)),
    querySelectorAll: () => [] as any[],
    querySelector: () => null,
    addEventListener: () => {},
    createElement: () => {
      let text = '';
      return {
        set textContent(v: string) { text = v; },
        get innerHTML() { return escapeHtml(text); },
      };
    },
  };
  // The evaluated string is the report our own generator just produced.
  runInNewContext(script, { document: documentStub, window: {} });
  const onNavClick = handlers.get('main-nav:click');
  if (!onNavClick) throw new Error('report script did not register the nav listener');
  onNavClick({ target: { closest: () => ({ dataset: { page: 'findings' } }) } });
  return { overview: node('page-overview').innerHTML, findings: node('page-findings').innerHTML };
}

/** The MITRE cell of each findings-table row, in order. */
function mitreCells(page: string): string[] {
  const cells: string[] = [];
  const row = /<td><span class="badge-owasp">[^<]*<\/span><\/td><td>(.*?)<\/td>/g;
  let m: RegExpExecArray | null;
  while ((m = row.exec(page)) !== null) cells.push(m[1]);
  return cells;
}

describe('frameworkTags', () => {
  it('lists the OWASP and ATLAS ids when both are set', () => {
    expect(frameworkTags(withAtlas('SHIELD-CRED-001', 'AML.T0055'))).toEqual(['ASI04', 'AML.T0055']);
  });

  it('leaves a null ATLAS id out', () => {
    expect(frameworkTags(withAtlas('SHIELD-CRED-001', null))).toEqual(['ASI04']);
  });
});

describe('SARIF with a null ATLAS id', () => {
  it('writes only string tags on the rule', () => {
    const sarif = toSarif([classified(withAtlas('SHIELD-INT-003', null))], '0.0.0');
    const tags = sarif.runs[0].tool.driver.rules[0].properties.tags;
    expect(tags).toEqual([FINDING_CATALOG['SHIELD-INT-003'].owaspAgentic]);
    expect(JSON.stringify(sarif)).not.toContain('null');
  });
});

describe('shield HTML report with a null ATLAS id', () => {
  const nullRow = classified(withAtlas('SHIELD-INT-003', null));
  const idRow = classified(withAtlas('SHIELD-CRED-001', 'AML.T0055'));

  it('prints the no-value token in the MITRE column, never an empty badge', () => {
    const pages = renderPages([nullRow, idRow]);
    for (const page of [pages.overview, pages.findings]) {
      expect(page).not.toContain('<span class="badge-mitre"></span>');
      expect(mitreCells(page)).toEqual([
        '<span style="color:var(--dim)">--</span>',
        '<span class="badge-mitre">AML.T0055</span>',
      ]);
    }
  });

  it('keeps null out of the findings search text', () => {
    const page = renderPages([nullRow, idRow]).findings;
    const search = [...page.matchAll(/data-search="([^"]*)"/g)].map((m) => m[1]);
    expect(search).toHaveLength(2);
    expect(search[0]).not.toContain('null');
    expect(search[0]).toBe(
      ['SHIELD-INT-003', FINDING_CATALOG['SHIELD-INT-003'].title, FINDING_CATALOG['SHIELD-INT-003'].owaspAgentic,
        FINDING_CATALOG['SHIELD-INT-003'].category].join(' ').toLowerCase(),
    );
    expect(search[1]).toContain('aml.t0055');
  });
});
