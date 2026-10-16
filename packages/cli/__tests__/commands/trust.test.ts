import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { trust, _internals, formatRelativeTime } from '../../src/commands/trust.js';
import type { TrustOptions } from '../../src/commands/trust.js';
import type { TrustLookupResponse } from '../../src/commands/atp-types.js';

function makeTrustResponse(overrides?: Partial<TrustLookupResponse>): TrustLookupResponse {
  return {
    agentId: 'test-agent-uuid',
    name: '@anthropic/mcp-server-fetch',
    source: 'npm',
    version: '1.2.0',
    publisher: 'anthropic',
    publisherVerified: true,
    trustScore: 0.72,
    trustLevel: 'verified',
    posture: {
      hardeningPassRate: 0.89,
      oasbCompliance: 0.83,
      soulConformance: 'standard',
      attackSurfaceRisk: 'low',
      supplyChainHealth: 0.91,
      a2asCertified: false,
    },
    factors: {
      verification: 0.95,
      uptime: 0.85,
      actionSuccess: 0.89,
      securityAlerts: 0.70,
      compliance: 0.83,
      age: 0.92,
      drift: 0.90,
      feedback: 0.75,
    },
    packageType: 'mcp_server',
    displayType: 'MCP Server',
    capabilities: ['web:read', 'http:fetch', 'file:read'],
    supplyChain: {
      totalDependencies: 12,
      criticalVulnerabilities: 0,
      highVulnerabilities: 1,
      lastPublished: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString(),
      maintainerCount: 3,
    },
    lastScanned: '2026-03-10T00:00:00Z',
    // Default uses a placeholder domain so tests exercise the normal render
    // path. Tests covering the dead-host suppression override this with a
    // known-dead host (registry.opena2a.org) explicitly.
    profileUrl: 'https://test-registry.example.com/agents/test-agent-uuid',
    ...overrides,
  };
}

function captureStdout(fn: () => Promise<number>): Promise<{ exitCode: number; output: string }> {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  process.stdout.write = ((chunk: any) => {
    chunks.push(String(chunk));
    return true;
  }) as any;

  return fn().then(exitCode => {
    process.stdout.write = origWrite;
    return { exitCode, output: chunks.join('') };
  }).catch(err => {
    process.stdout.write = origWrite;
    throw err;
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('trust', () => {
  it('returns trust profile as JSON when found', async () => {
    const mockResponse = makeTrustResponse();
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: mockResponse,
    });

    const options: TrustOptions = {
      packageName: '@anthropic/mcp-server-fetch',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => trust(options));

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(output);
    expect(parsed.agentId).toBe('test-agent-uuid');
    expect(parsed.trustScore).toBe(0.72);
    expect(parsed.trustLevel).toBe('verified');
    expect(parsed.capabilities).toContain('web:read');
  });

  it('returns exit code 1 when package not found', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: false,
      status: 404,
    });
    vi.spyOn(_internals, 'fetchRegistrySearch').mockResolvedValue({
      ok: true,
      status: 200,
      data: { packages: [], total: 0 },
    });

    const options: TrustOptions = {
      packageName: 'nonexistent-package',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => trust(options));

    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(parsed.error).toBe('not_found');
    expect(parsed.package).toBe('nonexistent-package');
  });

  it('reads package.json when no package name provided', async () => {
    vi.spyOn(_internals, 'readLocalPackageName').mockReturnValue('my-local-package');
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse({ name: 'my-local-package' }),
    });

    const options: TrustOptions = {
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => trust(options));

    expect(exitCode).toBe(0);
    // source defaults to 'npm' when not explicitly provided
    expect(_internals.fetchTrustLookup).toHaveBeenCalledWith(
      'https://test-registry.example.com',
      'my-local-package',
      'npm',
    );
  });

  it('returns error when no package name and no package.json', async () => {
    vi.spyOn(_internals, 'readLocalPackageName').mockReturnValue(null);

    const options: TrustOptions = {
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => trust(options));

    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(parsed.error).toBeDefined();
  });

  it('passes source parameter to API', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse({ source: 'pypi' }),
    });

    const options: TrustOptions = {
      packageName: 'langchain',
      source: 'pypi',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    await captureStdout(() => trust(options));

    expect(_internals.fetchTrustLookup).toHaveBeenCalledWith(
      'https://test-registry.example.com',
      'langchain',
      'pypi',
    );
  });

  it('handles network errors gracefully', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockRejectedValue(new Error('Network timeout'));

    const options: TrustOptions = {
      packageName: 'some-package',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => trust(options));

    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(parsed.error).toBe('request_failed');
    expect(parsed.message).toContain('Network timeout');
  });

  it('produces text output with all sections', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse(),
    });

    const options: TrustOptions = {
      packageName: '@anthropic/mcp-server-fetch',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'text',
    };

    const { exitCode, output } = await captureStdout(() => trust(options));

    expect(exitCode).toBe(0);
    expect(output).toContain('@anthropic/mcp-server-fetch');
    expect(output).toContain('v1.2.0');
    expect(output).toContain('anthropic');
    expect(output).toContain('72%');
    expect(output).toContain('MCP Server');
    expect(output).toContain('Security Posture');
    expect(output).toContain('Supply Chain');
    expect(output).toContain('web:read');
    expect(output).toContain('Profile:');
    expect(output).toContain('Badge:');
  });

  it('suppresses Profile/Badge lines for known-dead registry hosts', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      // Registry backend still returns this dead hostname in some responses —
      // the CLI should hide the link entirely and show a placeholder instead.
      data: makeTrustResponse({
        profileUrl: 'https://registry.opena2a.org/agents/test-agent-uuid',
      }),
    });

    const options: TrustOptions = {
      packageName: '@anthropic/mcp-server-fetch',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'text',
    };

    const { output } = await captureStdout(() => trust(options));

    expect(output).not.toContain('https://registry.opena2a.org');
    expect(output).not.toContain('Badge:');
    // Post-#123: Registry is live; only the per-package profile URL is dead.
    // The placeholder must not imply the Registry itself is offline.
    expect(output).not.toContain('Registry launches soon');
    expect(output).toContain('Profile: not available for this package');
  });

  it('falls back to formatted packageType when displayType is absent', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse({ displayType: undefined, packageType: 'a2a_agent' }),
    });

    const options: TrustOptions = {
      packageName: 'some-agent',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'text',
    };

    const { output } = await captureStdout(() => trust(options));
    expect(output).toContain('A2A Agent');
  });

  it('shows trust factors in verbose mode', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse(),
    });

    const options: TrustOptions = {
      packageName: '@anthropic/mcp-server-fetch',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'text',
      verbose: true,
    };

    const { output } = await captureStdout(() => trust(options));

    expect(output).toContain('Trust Factors');
    expect(output).toContain('verification');
    expect(output).toContain('uptime');
  });

  it('JSON output contains all required fields', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse(),
    });

    const options: TrustOptions = {
      packageName: '@anthropic/mcp-server-fetch',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { output } = await captureStdout(() => trust(options));

    const parsed = JSON.parse(output);
    expect(parsed).toHaveProperty('agentId');
    expect(parsed).toHaveProperty('name');
    expect(parsed).toHaveProperty('source');
    expect(parsed).toHaveProperty('version');
    expect(parsed).toHaveProperty('publisher');
    expect(parsed).toHaveProperty('publisherVerified');
    expect(parsed).toHaveProperty('trustScore');
    expect(parsed).toHaveProperty('trustLevel');
    expect(parsed).toHaveProperty('posture');
    expect(parsed).toHaveProperty('factors');
    expect(parsed).toHaveProperty('capabilities');
    expect(parsed).toHaveProperty('supplyChain');
    expect(parsed).toHaveProperty('lastScanned');
    expect(parsed).toHaveProperty('profileUrl');
  });

  it('handles discovered trust level with low score', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse({
        trustScore: 0.1,
        trustLevel: 'discovered',
        publisherVerified: false,
      }),
    });

    const options: TrustOptions = {
      packageName: 'some-discovered-agent',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => trust(options));

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(output);
    expect(parsed.trustLevel).toBe('discovered');
    expect(parsed.trustScore).toBe(0.1);
  });
});

describe('trust stale copy + zero-downloads (#123)', () => {
  it('suppresses Downloads line when Registry returns 0 (stale backfill)', async () => {
    const data = makeTrustResponse({
      profileUrl: 'https://opena2a.org/agents/express',
      supplyChain: {
        criticalVulnerabilities: 0,
        highVulnerabilities: 0,
        mediumVulnerabilities: 0,
        lowVulnerabilities: 0,
        lastPublished: new Date().toISOString(),
        maintainerCount: 5,
        weeklyDownloads: 0,
      },
    });
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({ ok: true, status: 200, data });

    const { output } = await captureStdout(() => trust({ packageName: 'express', ci: true, format: 'text' }));
    expect(output).not.toMatch(/Downloads:\s+0\/week/);
  });

  it("does NOT emit 'Registry launches soon' for dead-host profile URLs", async () => {
    const data = makeTrustResponse({ profileUrl: 'https://registry.oa2a.org/agents/express' });
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({ ok: true, status: 200, data });

    const { output } = await captureStdout(() => trust({ packageName: 'express', ci: true, format: 'text' }));
    expect(output).not.toContain('Registry launches soon');
    expect(output).toContain('Profile: not available for this package');
  });

  it('shows real Downloads count when > 0', async () => {
    const data = makeTrustResponse({
      profileUrl: 'https://opena2a.org/agents/express',
      supplyChain: {
        criticalVulnerabilities: 0,
        highVulnerabilities: 0,
        mediumVulnerabilities: 0,
        lowVulnerabilities: 0,
        lastPublished: new Date().toISOString(),
        maintainerCount: 5,
        weeklyDownloads: 35_000_000,
      },
    });
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({ ok: true, status: 200, data });

    const { output } = await captureStdout(() => trust({ packageName: 'express', ci: true, format: 'text' }));
    expect(output).toContain('35,000,000/week');
  });
});

describe('trust record fields: verdict, unscanned score, stale scan, placeholder version', () => {
  const DAY_MS = 24 * 60 * 60 * 1000;

  // The shape the Registry returned for lodash on 2026-10-16: no scan on
  // record, a registry-listing score, and the placeholder version.
  function unscannedRecord(overrides?: Partial<TrustLookupResponse>): TrustLookupResponse {
    return makeTrustResponse({
      name: 'lodash',
      version: '0.0.0-discovered',
      publisherVerified: false,
      trustScore: 0.4,
      trustLevel: 'discovered',
      posture: undefined,
      factors: undefined,
      capabilities: undefined,
      scanSummary: {
        status: 'not_scanned',
        actionRequired: 'This package has not been scanned yet. Submit a scan: hackmyagent scan lodash',
      },
      supplyChain: {
        criticalVulnerabilities: 0,
        highVulnerabilities: 0,
        mediumVulnerabilities: 0,
        lowVulnerabilities: 0,
        lastPublished: '2026-03-04T03:03:39Z',
        maintainerCount: 0,
        weeklyDownloads: 0,
      },
      lastScanned: undefined,
      profileUrl: 'https://registry.opena2a.org/agents/test-agent-uuid',
      ...overrides,
    });
  }

  // The shape the Registry returned for @modelcontextprotocol/server-filesystem
  // on 2026-10-16: scanned, one high finding, scan date past the stale threshold.
  function scannedWithHighFinding(lastScannedAt: string): TrustLookupResponse {
    return makeTrustResponse({
      name: '@modelcontextprotocol/server-filesystem',
      version: '0.0.0-discovered',
      trustScore: 0.79,
      trustLevel: 'scanned',
      posture: undefined,
      factors: undefined,
      capabilities: undefined,
      scanSummary: {
        status: 'warnings',
        lastScannedAt,
        findingsCount: 1,
        highCount: 1,
        actionRequired: '1 high-severity findings. Review recommended.',
      },
      supplyChain: {
        criticalVulnerabilities: 0,
        highVulnerabilities: 1,
        mediumVulnerabilities: 0,
        lowVulnerabilities: 0,
        lastPublished: '2026-02-20T02:29:37Z',
        maintainerCount: 0,
        weeklyDownloads: 248_336,
      },
      lastScanned: lastScannedAt,
    });
  }

  async function renderText(data: TrustLookupResponse): Promise<string> {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({ ok: true, status: 200, data });
    const { output } = await captureStdout(() =>
      trust({ packageName: data.name, registryUrl: 'https://test-registry.example.com', ci: true, format: 'text' }));
    return output;
  }

  async function renderJson(data: TrustLookupResponse): Promise<any> {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({ ok: true, status: 200, data });
    const { output } = await captureStdout(() =>
      trust({ packageName: data.name, registryUrl: 'https://test-registry.example.com', ci: true, format: 'json' }));
    return JSON.parse(output);
  }

  it('prints no percentage for a record with no scan on file', async () => {
    const output = await renderText(unscannedRecord());
    expect(output).not.toContain('%');
    expect(output).toMatch(/Trust:\s+not scanned \(discovered\)/);
    // A finding count of 0 is a measurement; an unscanned record has none.
    expect(output).not.toMatch(/Findings:/);
  });

  it('prints no percentage when there is neither a scan summary nor a posture', async () => {
    const output = await renderText(unscannedRecord({ scanSummary: undefined }));
    expect(output).not.toContain('%');
    expect(output).toMatch(/Trust:\s+not scanned \(discovered\)/);
  });

  it('keeps the raw trustScore in JSON and marks it unscored', async () => {
    const parsed = await renderJson(unscannedRecord());
    expect(parsed.trustScore).toBe(0.4);
    expect(parsed.scored).toBe(false);
  });

  it('marks a scan-backed score as scored in JSON', async () => {
    const parsed = await renderJson(scannedWithHighFinding(new Date(Date.now() - 10 * DAY_MS).toISOString()));
    expect(parsed.trustScore).toBe(0.79);
    expect(parsed.scored).toBe(true);
  });

  it('marks a scan date older than 90 days as stale', async () => {
    const output = await renderText(scannedWithHighFinding(new Date(Date.now() - 228 * DAY_MS).toISOString()));
    expect(output).toMatch(/Last Scanned: .*\(stale\)/);
  });

  it('does not mark a scan date within 90 days as stale', async () => {
    const output = await renderText(scannedWithHighFinding(new Date(Date.now() - 30 * DAY_MS).toISOString()));
    expect(output).toMatch(/Last Scanned: /);
    expect(output).not.toContain('(stale)');
  });

  it('prints a Verdict that is not SAFE for a record with one high finding', async () => {
    const output = await renderText(scannedWithHighFinding(new Date(Date.now() - 228 * DAY_MS).toISOString()));
    const verdictLines = output.split('\n').filter(l => /^Verdict:/.test(l));
    expect(verdictLines).toHaveLength(1);
    expect(verdictLines[0]).toMatch(/^Verdict:\s+WARNING/);
    expect(verdictLines[0]).not.toContain('SAFE');
  });

  it('prints a SAFE Verdict for a clean scanned record', async () => {
    const data = scannedWithHighFinding(new Date(Date.now() - 10 * DAY_MS).toISOString());
    data.scanSummary = { status: 'clean', lastScannedAt: data.scanSummary!.lastScannedAt, findingsCount: 0, highCount: 0 };
    data.supplyChain = { ...data.supplyChain!, highVulnerabilities: 0 };
    const output = await renderText(data);
    expect(output).toMatch(/^Verdict:\s+SAFE/m);
    expect(output).toMatch(/Trust:\s+79% \(scanned\)/);
  });

  it('prints a NOT SCANNED Verdict for an unscanned record', async () => {
    const output = await renderText(unscannedRecord());
    expect(output).toMatch(/^Verdict:\s+NOT SCANNED/m);
    expect(output).not.toContain('SAFE');
  });

  it('prints a BLOCKED Verdict when the Registry blocks the package', async () => {
    const data = scannedWithHighFinding(new Date(Date.now() - 10 * DAY_MS).toISOString());
    data.trustLevel = 'blocked';
    const output = await renderText(data);
    expect(output).toMatch(/^Verdict:\s+BLOCKED/m);
  });

  it('does not print the 0.0.0-discovered placeholder as a version', async () => {
    const output = await renderText(unscannedRecord());
    expect(output).not.toContain('v0.0.0');
    expect(output).toContain('lodash version unknown (not scanned)');
  });

  it('does not print the placeholder version in verbose request details', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({ ok: true, status: 200, data: unscannedRecord() });
    const { output } = await captureStdout(() =>
      trust({ packageName: 'lodash', registryUrl: 'https://test-registry.example.com', ci: true, format: 'text', verbose: true }));
    expect(output).not.toContain('0.0.0-discovered');
  });

  it('does not print the Registry ingest timestamp as the publish date', async () => {
    const output = await renderText(scannedWithHighFinding(new Date(Date.now() - 228 * DAY_MS).toISOString()));
    expect(output).not.toMatch(/Published:/);
  });
});

describe('formatRelativeTime (#122)', () => {
  it("returns 'never' for null", () => {
    expect(formatRelativeTime(null)).toBe('never');
  });

  it("returns 'never' for undefined", () => {
    expect(formatRelativeTime(undefined)).toBe('never');
  });

  it("returns 'never' for empty string", () => {
    expect(formatRelativeTime('')).toBe('never');
  });

  it("returns 'never' for unparseable date", () => {
    expect(formatRelativeTime('not-a-date')).toBe('never');
  });

  it("never returns 'NaN months ago' (regression for #122)", () => {
    expect(formatRelativeTime(null)).not.toContain('NaN');
    expect(formatRelativeTime(undefined)).not.toContain('NaN');
    expect(formatRelativeTime('garbage')).not.toContain('NaN');
  });

  it("formats a valid recent timestamp as 'today' or 'N days ago'", () => {
    const now = new Date().toISOString();
    expect(formatRelativeTime(now)).toBe('today');
    const threeDaysAgo = new Date(Date.now() - 3 * 86400_000).toISOString();
    expect(formatRelativeTime(threeDaysAgo)).toBe('3 days ago');
  });
});
