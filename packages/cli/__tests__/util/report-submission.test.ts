// Regression: the identity fields a scan report reaches the Registry with.
//
// submitScanReport sent the report's `packageType` as `type`, a field the
// Registry's publish endpoint does not read, so every stored report carried
// no package type; and it sent the same value as the ecosystem of the queued
// copy, which the Registry keeps only for the npm, pypi and github
// ecosystems, so a report typed `mcp_server` was skipped there. The Registry
// reads the package type from `projectType` and the ecosystem from
// `ecosystem`, and that is where each value now goes.

import { describe, it, expect, vi, beforeEach } from 'vitest';

const registry = vi.hoisted(() => ({
  publishScan: vi.fn(async () => ({ accepted: true, publishId: 'published-0001' })),
}));

const queue = vi.hoisted(() => ({
  scanResult: vi.fn(async () => undefined),
}));

vi.mock('@opena2a/registry-client', () => ({
  RegistryClient: class {
    publishScan = registry.publishScan;
  },
  RegistryApiError: class extends Error {
    statusCode?: number;
  },
  firstPartySignerFromEnv: () => undefined,
}));

vi.mock('@opena2a/contribute', () => ({
  contribute: { scanResult: queue.scanResult },
}));

import { submitScanReport, type ScanReport } from '../../src/util/report-submission.js';

const REGISTRY_URL = 'https://api.oa2a.org';

function report(identity: Pick<ScanReport, 'packageName' | 'packageType' | 'ecosystem'>): ScanReport {
  return {
    ...identity,
    scannerName: 'HackMyAgent',
    scannerVersion: '0.30.0',
    overallScore: 90,
    scanDurationMs: 5,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 1,
    lowCount: 0,
    infoCount: 0,
    verdict: 'pass',
    findings: [{ findingId: 'HMA-001', severity: 'medium', category: 'config', title: 'A finding' }],
  };
}

function published(): Record<string, unknown> {
  expect(registry.publishScan).toHaveBeenCalledTimes(1);
  return registry.publishScan.mock.calls[0][0] as unknown as Record<string, unknown>;
}

function queued(): Record<string, unknown> {
  expect(queue.scanResult).toHaveBeenCalledTimes(1);
  return queue.scanResult.mock.calls[0][0] as unknown as Record<string, unknown>;
}

describe('submitScanReport identity fields', () => {
  beforeEach(() => {
    registry.publishScan.mockClear();
    queue.scanResult.mockClear();
  });

  it('a detect report of an MCP server publishes its type as projectType and npm as the ecosystem', async () => {
    const sent = await submitScanReport(REGISTRY_URL, report({
      packageName: '@modelcontextprotocol/server-filesystem',
      packageType: 'mcp_server',
      ecosystem: 'npm',
    }));

    expect(sent).toBe(true);
    const body = published();
    expect(body.name).toBe('@modelcontextprotocol/server-filesystem');
    expect(body.projectType).toBe('mcp_server');
    expect(body.ecosystem).toBe('npm');
    expect(body).not.toHaveProperty('type');
  });

  it('the queued copy of a detect report names npm as its ecosystem', async () => {
    await submitScanReport(REGISTRY_URL, report({
      packageName: '@modelcontextprotocol/server-filesystem',
      packageType: 'mcp_server',
      ecosystem: 'npm',
    }));

    const event = queued();
    expect(event.packageName).toBe('@modelcontextprotocol/server-filesystem');
    expect(event.ecosystem).toBe('npm');
  });

  // review sends the ecosystem in packageType, with no package type: the
  // Registry resolves the package by name, and that stays so.
  it('a review report typed npm publishes npm as the ecosystem and no projectType', async () => {
    await submitScanReport(REGISTRY_URL, report({ packageName: 'revfix', packageType: 'npm' }));

    const body = published();
    expect(body.name).toBe('revfix');
    expect(body.ecosystem).toBe('npm');
    expect(body).not.toHaveProperty('projectType');
    expect(body).not.toHaveProperty('type');
    expect(queued().ecosystem).toBe('npm');
  });

  it('a report with no package type publishes neither projectType nor ecosystem', async () => {
    await submitScanReport(REGISTRY_URL, report({ packageName: 'revfix' }));

    const body = published();
    expect(body).not.toHaveProperty('projectType');
    expect(body).not.toHaveProperty('ecosystem');
    expect(body).not.toHaveProperty('type');
  });

  it('the rest of the published scan is unchanged', async () => {
    await submitScanReport(REGISTRY_URL, report({
      packageName: '@modelcontextprotocol/server-filesystem',
      packageType: 'mcp_server',
      ecosystem: 'npm',
    }));

    const body = published();
    expect(body.score).toBe(90);
    expect(body.maxScore).toBe(100);
    expect(body.tool).toBe('HackMyAgent');
    expect(body.toolVersion).toBe('0.30.0');
    expect(body.verdict).toBe('pass');
    expect(body.findings).toEqual([{
      checkId: 'HMA-001',
      name: 'A finding',
      severity: 'medium',
      passed: false,
      message: 'A finding',
      category: 'config',
      attackClass: undefined,
    }]);
  });
});
