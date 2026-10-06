import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { trust, _internals as trustInternals } from '../../src/commands/trust.js';
import { claim, _internals as claimInternals } from '../../src/commands/claim.js';
import type { TrustLookupResponse, ClaimResponse } from '../../src/commands/atp-types.js';

// The badge line is printed from the badgeImageUrl and badgeLinkUrl the
// Registry returns in the lookup response. The CLI never builds a badge URL
// itself: rewriting profileUrl produced a path the profile host does not serve.

const PACKAGES = [
  { name: 'express', source: 'npm', agentId: 'unscoped-agent-uuid' },
  { name: '@modelcontextprotocol/server-filesystem', source: 'npm', agentId: 'scoped-agent-uuid' },
];

function badgeFor(name: string, source: string): { badgeImageUrl: string; badgeLinkUrl: string } {
  const q = new URLSearchParams({ package: name, source }).toString();
  return {
    badgeImageUrl: `https://badges.example.com/v1/trust/badge.svg?${q}`,
    badgeLinkUrl: `https://profiles.example.com/trust?${q}`,
  };
}

function lookup(name: string, source: string, agentId: string, overrides?: Partial<TrustLookupResponse>): TrustLookupResponse {
  return {
    agentId,
    name,
    source,
    version: '1.0.0',
    publisher: 'someone',
    publisherVerified: false,
    trustScore: 0.5,
    trustLevel: 'discovered',
    lastScanned: '',
    profileUrl: `https://live-profiles.example.com/agents/${agentId}`,
    ...overrides,
  };
}

function claimResponse(agentId: string, profileUrl: string): ClaimResponse {
  return {
    success: true,
    agentId,
    previousTrustLevel: 'discovered',
    newTrustLevel: 'claimed',
    previousTrustScore: 0.15,
    newTrustScore: 0.35,
    profileUrl,
  };
}

async function captureStdout(fn: () => Promise<number>): Promise<{ exitCode: number; output: string }> {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  process.stdout.write = ((chunk: any) => {
    chunks.push(String(chunk));
    return true;
  }) as any;
  try {
    const exitCode = await fn();
    return { exitCode, output: chunks.join('') };
  } finally {
    process.stdout.write = origWrite;
  }
}

function runTrust(data: TrustLookupResponse) {
  vi.spyOn(trustInternals, 'fetchTrustLookup').mockResolvedValue({ ok: true, status: 200, data });
  return captureStdout(() => trust({
    packageName: data.name,
    source: data.source,
    registryUrl: 'https://test-registry.example.com',
    ci: true,
    format: 'text',
  }));
}

function runClaim(data: TrustLookupResponse) {
  vi.spyOn(claimInternals, 'fetchTrustLookup').mockResolvedValue({ ok: true, status: 200, data });
  vi.spyOn(claimInternals, 'verifyNpmOwnership').mockResolvedValue({ method: 'npm', identity: 'someone', evidence: '{}' });
  vi.spyOn(claimInternals, 'generateKeypair').mockResolvedValue({ publicKey: 'pub', privateKey: 'priv' });
  vi.spyOn(claimInternals, 'submitClaim').mockResolvedValue({
    ok: true,
    status: 200,
    data: claimResponse(data.agentId, data.profileUrl),
  });
  vi.spyOn(claimInternals, 'storeKeypair').mockResolvedValue('/tmp/keys');
  return captureStdout(() => claim({
    packageName: data.name,
    source: data.source,
    registryUrl: 'https://test-registry.example.com',
    ci: true,
    format: 'text',
  }));
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('trust badge line', () => {
  for (const pkg of PACKAGES) {
    it(`prints the Registry's badge URLs verbatim for ${pkg.name}`, async () => {
      const badge = badgeFor(pkg.name, pkg.source);
      const { exitCode, output } = await runTrust(lookup(pkg.name, pkg.source, pkg.agentId, badge));

      expect(exitCode).toBe(0);
      expect(output).toContain(`Badge:   [![Trust](${badge.badgeImageUrl})](${badge.badgeLinkUrl})`);
      expect(output).not.toContain(`/v1/trust/${pkg.agentId}/badge.svg`);
    });
  }

  it('prints no badge line when the lookup response carries no badge URLs', async () => {
    const { output } = await runTrust(lookup('express', 'npm', 'unscoped-agent-uuid'));

    expect(output).toContain('Profile: https://live-profiles.example.com/agents/unscoped-agent-uuid');
    expect(output).not.toContain('Badge:');
    expect(output).not.toContain('badge.svg');
  });

  it('prints no badge line when only one of the two badge URLs is present', async () => {
    const { badgeImageUrl } = badgeFor('express', 'npm');
    const { output } = await runTrust(lookup('express', 'npm', 'unscoped-agent-uuid', { badgeImageUrl }));

    expect(output).not.toContain('Badge:');
  });

  it('does not print a badge URL that is not http or https', async () => {
    const { output } = await runTrust(lookup('express', 'npm', 'unscoped-agent-uuid', {
      badgeImageUrl: 'javascript:alert(1)',
      badgeLinkUrl: 'https://profiles.example.com/trust?package=express',
    }));

    expect(output).not.toContain('Badge:');
    expect(output).not.toContain('javascript:');
  });

  it('prints the badge line independently of the profile host', async () => {
    const badge = badgeFor('@modelcontextprotocol/server-filesystem', 'npm');
    const { output } = await runTrust(lookup('@modelcontextprotocol/server-filesystem', 'npm', 'scoped-agent-uuid', {
      profileUrl: 'https://registry.opena2a.org/agents/scoped-agent-uuid',
      ...badge,
    }));

    expect(output).not.toContain('https://registry.opena2a.org');
    expect(output).toContain(`Badge:   [![Trust](${badge.badgeImageUrl})](${badge.badgeLinkUrl})`);
  });
});

describe('claim badge snippet', () => {
  for (const pkg of PACKAGES) {
    it(`prints the Registry's badge URLs verbatim for ${pkg.name}`, async () => {
      const badge = badgeFor(pkg.name, pkg.source);
      const { exitCode, output } = await runClaim(lookup(pkg.name, pkg.source, pkg.agentId, badge));

      expect(exitCode).toBe(0);
      expect(output).toContain('Add badge to README:');
      expect(output).toContain(`[![Trust](${badge.badgeImageUrl})](${badge.badgeLinkUrl})`);
      expect(output).not.toContain(`/v1/trust/${pkg.agentId}/badge.svg`);
    });
  }

  it('prints no badge snippet when the lookup response carries no badge URLs', async () => {
    const { exitCode, output } = await runClaim(lookup('express', 'npm', 'unscoped-agent-uuid'));

    expect(exitCode).toBe(0);
    expect(output).toContain('Claimed successfully');
    expect(output).not.toContain('Add badge to README');
    expect(output).not.toContain('badge.svg');
  });
});
