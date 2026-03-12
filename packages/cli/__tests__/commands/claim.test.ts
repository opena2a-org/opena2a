import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { claim, _internals } from '../../src/commands/claim.js';
import type { ClaimOptions } from '../../src/commands/claim.js';
import type { TrustLookupResponse, ClaimResponse } from '../../src/commands/atp-types.js';

function makeTrustResponse(overrides?: Partial<TrustLookupResponse>): TrustLookupResponse {
  return {
    agentId: 'test-agent-uuid',
    name: '@anthropic/mcp-server-fetch',
    source: 'npm',
    version: '1.2.0',
    publisher: 'anthropic',
    publisherVerified: false,
    trustScore: 0.15,
    trustLevel: 'discovered',
    posture: {
      hardeningPassRate: 0,
      oasbCompliance: 0,
      soulConformance: 'none',
      attackSurfaceRisk: 'unknown',
      supplyChainHealth: 0.5,
      a2asCertified: false,
    },
    factors: {
      verification: 0,
      uptime: 0.5,
      actionSuccess: 0,
      securityAlerts: 0,
      compliance: 0,
      age: 0.8,
      drift: 1.0,
      feedback: 0.75,
    },
    capabilities: [],
    supplyChain: {
      totalDependencies: 5,
      criticalVulnerabilities: 0,
      highVulnerabilities: 0,
      lastPublished: new Date().toISOString(),
      maintainerCount: 1,
    },
    lastScanned: '',
    profileUrl: 'https://registry.opena2a.org/agents/test-agent-uuid',
    ...overrides,
  };
}

function makeClaimResponse(overrides?: Partial<ClaimResponse>): ClaimResponse {
  return {
    success: true,
    agentId: 'test-agent-uuid',
    previousTrustLevel: 'discovered',
    newTrustLevel: 'claimed',
    previousTrustScore: 0.15,
    newTrustScore: 0.35,
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

describe('claim', () => {
  it('successfully claims an unclaimed package', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse(),
    });
    vi.spyOn(_internals, 'verifyNpmOwnership').mockResolvedValue({
      method: 'npm',
      identity: 'testuser',
      evidence: '{}',
    });
    vi.spyOn(_internals, 'generateKeypair').mockResolvedValue({
      publicKey: 'mock-public-key',
      privateKey: 'mock-private-key',
    });
    vi.spyOn(_internals, 'submitClaim').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeClaimResponse(),
    });
    vi.spyOn(_internals, 'storeKeypair').mockResolvedValue('/tmp/.opena2a/keys');

    const options: ClaimOptions = {
      packageName: '@anthropic/mcp-server-fetch',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => claim(options));

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(output);
    expect(parsed.success).toBe(true);
    expect(parsed.newTrustLevel).toBe('claimed');
    expect(parsed.newTrustScore).toBe(0.35);
  });

  it('returns error when package not found in registry', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: false,
      status: 404,
    });

    const options: ClaimOptions = {
      packageName: 'nonexistent-package',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => claim(options));

    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(parsed.error).toBe('not_found');
  });

  it('returns error when package already claimed', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse({
        trustLevel: 'claimed',
        publisher: 'someone-else',
      }),
    });

    const options: ClaimOptions = {
      packageName: '@anthropic/mcp-server-fetch',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => claim(options));

    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(parsed.error).toBe('already_claimed');
    expect(parsed.publisher).toBe('someone-else');
  });

  it('returns error when already verified', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse({
        trustLevel: 'verified',
        publisher: 'verified-user',
      }),
    });

    const options: ClaimOptions = {
      packageName: 'test-package',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => claim(options));

    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(parsed.error).toBe('already_claimed');
  });

  it('returns error when ownership verification fails', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse(),
    });
    vi.spyOn(_internals, 'verifyNpmOwnership').mockResolvedValue(null);
    vi.spyOn(_internals, 'verifyGithubOwnership').mockResolvedValue(null);

    const options: ClaimOptions = {
      packageName: '@anthropic/mcp-server-fetch',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => claim(options));

    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(parsed.error).toBe('verification_failed');
  });

  it('reads package.json when no package name provided', async () => {
    vi.spyOn(_internals, 'readLocalPackageName').mockReturnValue('my-local-package');
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse({ name: 'my-local-package' }),
    });
    vi.spyOn(_internals, 'verifyNpmOwnership').mockResolvedValue({
      method: 'npm',
      identity: 'testuser',
      evidence: '{}',
    });
    vi.spyOn(_internals, 'generateKeypair').mockResolvedValue({
      publicKey: 'mock-pub',
      privateKey: 'mock-priv',
    });
    vi.spyOn(_internals, 'submitClaim').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeClaimResponse(),
    });
    vi.spyOn(_internals, 'storeKeypair').mockResolvedValue('/tmp/keys');

    const options: ClaimOptions = {
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode } = await captureStdout(() => claim(options));

    expect(exitCode).toBe(0);
    expect(_internals.fetchTrustLookup).toHaveBeenCalledWith(
      'https://test-registry.example.com',
      'my-local-package',
      'npm',
    );
  });

  it('returns error when no package name and no package.json', async () => {
    vi.spyOn(_internals, 'readLocalPackageName').mockReturnValue(null);

    const options: ClaimOptions = {
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => claim(options));

    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(parsed.error).toBeDefined();
  });

  it('falls back to GitHub verification when npm fails', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse(),
    });
    vi.spyOn(_internals, 'verifyNpmOwnership').mockResolvedValue(null);
    vi.spyOn(_internals, 'verifyGithubOwnership').mockResolvedValue({
      method: 'github',
      identity: 'owner/repo',
      evidence: '{}',
    });
    vi.spyOn(_internals, 'generateKeypair').mockResolvedValue({
      publicKey: 'mock-pub',
      privateKey: 'mock-priv',
    });
    vi.spyOn(_internals, 'submitClaim').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeClaimResponse(),
    });
    vi.spyOn(_internals, 'storeKeypair').mockResolvedValue('/tmp/keys');

    const options: ClaimOptions = {
      packageName: 'test-package',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode } = await captureStdout(() => claim(options));

    expect(exitCode).toBe(0);
    expect(_internals.verifyGithubOwnership).toHaveBeenCalled();
  });

  it('handles claim submission failure gracefully', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse(),
    });
    vi.spyOn(_internals, 'verifyNpmOwnership').mockResolvedValue({
      method: 'npm',
      identity: 'testuser',
      evidence: '{}',
    });
    vi.spyOn(_internals, 'generateKeypair').mockResolvedValue({
      publicKey: 'mock-pub',
      privateKey: 'mock-priv',
    });
    vi.spyOn(_internals, 'submitClaim').mockResolvedValue({
      ok: false,
      status: 500,
      data: {
        success: false,
        agentId: 'test-agent-uuid',
        previousTrustLevel: 'discovered',
        newTrustLevel: 'discovered',
        previousTrustScore: 0.15,
        newTrustScore: 0.15,
        profileUrl: '',
        error: 'Internal server error',
      },
    });

    const options: ClaimOptions = {
      packageName: 'test-package',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => claim(options));

    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(parsed.error).toBe('claim_failed');
  });

  it('produces text output with claim steps', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse(),
    });
    vi.spyOn(_internals, 'verifyNpmOwnership').mockResolvedValue({
      method: 'npm',
      identity: 'testuser',
      evidence: '{}',
    });
    vi.spyOn(_internals, 'generateKeypair').mockResolvedValue({
      publicKey: 'mock-pub',
      privateKey: 'mock-priv',
    });
    vi.spyOn(_internals, 'submitClaim').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeClaimResponse(),
    });
    vi.spyOn(_internals, 'storeKeypair').mockResolvedValue('/tmp/keys');

    const options: ClaimOptions = {
      packageName: '@anthropic/mcp-server-fetch',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'text',
    };

    const { exitCode, output } = await captureStdout(() => claim(options));

    expect(exitCode).toBe(0);
    expect(output).toContain('Claimed successfully');
    expect(output).toContain('claimed');
    expect(output).toContain('Next steps');
    expect(output).toContain('hackmyagent scan');
    expect(output).toContain('badge.svg');
  });

  it('handles network errors during lookup', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockRejectedValue(new Error('Connection refused'));

    const options: ClaimOptions = {
      packageName: 'test-package',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    const { exitCode, output } = await captureStdout(() => claim(options));

    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(parsed.error).toBe('lookup_failed');
  });

  it('passes source parameter correctly', async () => {
    vi.spyOn(_internals, 'fetchTrustLookup').mockResolvedValue({
      ok: true,
      status: 200,
      data: makeTrustResponse({ source: 'pypi' }),
    });
    vi.spyOn(_internals, 'verifyNpmOwnership').mockResolvedValue(null);
    vi.spyOn(_internals, 'verifyGithubOwnership').mockResolvedValue(null);

    const options: ClaimOptions = {
      packageName: 'langchain',
      source: 'pypi',
      registryUrl: 'https://test-registry.example.com',
      ci: true,
      format: 'json',
    };

    await captureStdout(() => claim(options));

    expect(_internals.fetchTrustLookup).toHaveBeenCalledWith(
      'https://test-registry.example.com',
      'langchain',
      'pypi',
    );
  });
});
