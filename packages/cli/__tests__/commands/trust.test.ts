import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { trust, _internals } from '../../src/commands/trust.js';
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
    profileUrl: 'https://registry.opena2a.org/agents/test-agent-uuid',
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
