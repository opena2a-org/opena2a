import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// What submitScanReport hands the Registry: the contribute event, the publish
// request, and the legacy POST it falls back to when the publish endpoint
// answers 404. All three are recording stubs, so nothing leaves the machine.
const sent = vi.hoisted(() => ({
  events: [] as Array<Record<string, unknown>>,
  publishes: [] as Array<Record<string, unknown>>,
  legacyPosts: [] as Array<{ url: string; body: Record<string, unknown> }>,
  publishNotFound: false,
}));
vi.mock('@opena2a/contribute', () => ({
  contribute: {
    scanResult: async (params: Record<string, unknown>) => { sent.events.push({ ...params }); },
  },
}));
vi.mock('@opena2a/registry-client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@opena2a/registry-client')>();
  class RecordingClient extends actual.RegistryClient {
    async publishScan(submission: Parameters<InstanceType<typeof actual.RegistryClient>['publishScan']>[0]) {
      sent.publishes.push({ ...submission });
      if (sent.publishNotFound) {
        throw new actual.RegistryApiError('not found', 'not_found', 404);
      }
      return { accepted: true };
    }
  }
  return { ...actual, RegistryClient: RecordingClient };
});

import {
  submitScanReport,
  normalizeDetectReport,
  normalizeGovernanceReport,
  CANONICAL_REGISTRY_URL,
  type ScanReport,
} from '../../src/util/report-submission.js';
import { getVersion } from '../../src/util/version.js';

const counts = {
  overallScore: 40,
  scanDurationMs: 0,
  criticalCount: 0,
  highCount: 1,
  mediumCount: 0,
  lowCount: 0,
  infoCount: 0,
  verdict: 'fail',
  findings: [],
};

// The report `opena2a detect` builds for its Shadow AI audit.
function detectAuditReport(): ScanReport {
  return normalizeDetectReport({
    summary: { governanceScore: 40, totalAgents: 0, mcpServers: 1, aiConfigs: 0 },
    agents: [],
    mcpServers: [{ name: 'filesystem', capabilities: ['filesystem'], source: '.mcp.json (project)' }],
    findings: [{ severity: 'high', category: 'mcp', title: 'Unverified MCP server', whyItMatters: 'filesystem' }],
    scanDirectory: '/project',
  });
}

// The reports the other callers build: `detect --registry --auto-scan` names
// an MCP server by its key in .mcp.json, `identity trust` names its score
// `agent-trust`, and a scan-soul result names the governance file.
function labelledReports(): ScanReport[] {
  return [
    detectAuditReport(),
    { packageName: 'filesystem', packageType: 'mcp_server', scannerName: 'HackMyAgent', scannerVersion: '1.0.0', ...counts },
    { packageName: 'agent-trust', packageType: 'trust', scannerName: 'opena2a-identity', scannerVersion: getVersion(), ...counts },
    normalizeGovernanceReport({
      file: 'SOUL.md',
      score: 30,
      grade: 'needs-attention',
      domains: [{ domain: 'Trust Hierarchy', controls: [{ id: 'SOUL-TH-001', name: 'Trust hierarchy', passed: false }], passed: 0, total: 1 }],
    })!,
  ];
}

function packageReport(): ScanReport {
  return {
    packageName: 'contribution-node-fixture',
    ecosystem: 'npm',
    scannerName: 'opena2a-review',
    scannerVersion: getVersion(),
    ...counts,
  };
}

describe('submitScanReport sends a scan only under a Registry ecosystem', () => {
  beforeEach(() => {
    sent.events.length = 0;
    sent.publishes.length = 0;
    sent.legacyPosts.length = 0;
    sent.publishNotFound = false;
    vi.stubGlobal('fetch', async (url: string | URL, init?: RequestInit) => {
      sent.legacyPosts.push({ url: String(url), body: JSON.parse(String(init?.body ?? '{}')) });
      return new Response(null, { status: 200 });
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends nothing for a report without an ecosystem', async () => {
    // These went out with the scan type (`detect`, `mcp_server`, `trust`,
    // `governance`) as the contribute event's ecosystem and the label as the
    // published package name, which the Registry files as an npm package.
    for (const report of labelledReports()) {
      expect(report.ecosystem).toBeUndefined();
      expect(await submitScanReport(CANONICAL_REGISTRY_URL, report)).toBe(false);
    }

    expect(sent.events).toEqual([]);
    expect(sent.publishes).toEqual([]);
    expect(sent.legacyPosts).toEqual([]);
  });

  it('sends a report with an ecosystem under that ecosystem in both requests', async () => {
    expect(await submitScanReport(CANONICAL_REGISTRY_URL, packageReport())).toBe(true);

    expect(sent.events).toHaveLength(1);
    expect(sent.events[0]).toMatchObject({
      packageName: 'contribution-node-fixture',
      ecosystem: 'npm',
      toolVersion: getVersion(),
    });
    expect(sent.publishes).toHaveLength(1);
    expect(sent.publishes[0]).toMatchObject({
      name: 'contribution-node-fixture',
      ecosystem: 'npm',
      toolVersion: getVersion(),
    });
    expect(sent.legacyPosts).toEqual([]);
  });

  it('sends the running CLI version as clientVersion to the legacy endpoint', async () => {
    sent.publishNotFound = true;

    expect(await submitScanReport(CANONICAL_REGISTRY_URL, packageReport())).toBe(true);

    // It used to send the literal 0.1.0 whatever version ran.
    expect(getVersion()).not.toBe('0.1.0');
    expect(sent.publishes).toHaveLength(1);
    expect(sent.legacyPosts).toHaveLength(1);
    expect(sent.legacyPosts[0].url).toBe(`${CANONICAL_REGISTRY_URL}/api/v1/trust/scan-report`);
    expect(sent.legacyPosts[0].body).toMatchObject({
      packageName: 'contribution-node-fixture',
      ecosystem: 'npm',
      clientVersion: getVersion(),
    });
  });

  it('names the running CLI version in the report detect builds', () => {
    // It used to carry the literal 0.6.3.
    expect(getVersion()).not.toBe('0.6.3');
    expect(detectAuditReport().scannerVersion).toBe(getVersion());
  });
});
