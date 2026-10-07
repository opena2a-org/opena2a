/**
 * `shield report --report <file>` tags each top violation with the framework
 * ids of the finding it classifies to. A finding that no MITRE ATLAS
 * technique describes carries `mitreAtlas: null`, and the violation's
 * `compliance` list must leave that out rather than carry `null` beside the
 * OWASP id. The catalog holds no such finding today, so classifyViolation is
 * wrapped here to return one with a null ATLAS id.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

vi.mock('../../src/shield/findings.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/shield/findings.js')>();
  return {
    ...actual,
    classifyViolation: (violation: Parameters<typeof actual.classifyViolation>[0]) => {
      const finding = actual.classifyViolation(violation);
      return finding === null ? null : { ...finding, mitreAtlas: null };
    },
  };
});

const { writeEvent, getShieldDir } = await import('../../src/shield/events.js');
const { FINDING_CATALOG } = await import('../../src/shield/findings.js');
const { shield } = await import('../../src/commands/shield.js');

let tempHome: string;
let reportDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-compliance-home-'));
  reportDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-compliance-out-'));
  _mockHomeDir = tempHome;
  getShieldDir();
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(reportDir, { recursive: true, force: true });
});

interface ReportPayload {
  report: {
    policyEvaluation: {
      topViolations: { action: string; findingId?: string; compliance?: unknown[] }[];
    };
  };
}

/** The JSON the HTML report embeds for its own script. */
function reportPayload(html: string): ReportPayload {
  const open = html.indexOf('>', html.indexOf('<script id="report-data"')) + 1;
  return JSON.parse(html.slice(open, html.indexOf('</script>', open))) as ReportPayload;
}

describe('shield report compliance tags with a null ATLAS id', () => {
  it('lists only the OWASP id for a violation whose finding has no ATLAS technique', async () => {
    writeEvent({
      source: 'arp',
      category: 'credential',
      severity: 'high',
      agent: null,
      sessionId: null,
      action: 'credential-access',
      target: 'ANTHROPIC_API_KEY',
      outcome: 'monitored',
      detail: {},
      orgId: null,
      managed: false,
      agentId: null,
    });

    const reportPath = path.join(reportDir, 'shield.html');
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const code = await shield({ subcommand: 'report', report: reportPath });
    vi.restoreAllMocks();

    expect(code).toBe(0);
    const violations = reportPayload(fs.readFileSync(reportPath, 'utf-8')).report.policyEvaluation.topViolations;
    const violation = violations.find(v => v.action === 'credential-access');
    expect(violation).toBeDefined();
    expect(violation!.findingId).toBe('SHIELD-CRED-001');
    expect(violation!.compliance).toEqual([FINDING_CATALOG['SHIELD-CRED-001'].owaspAgentic]);
  });
});
