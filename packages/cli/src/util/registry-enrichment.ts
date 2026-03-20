/**
 * Registry enrichment -- queries the OpenA2A Registry for community trust data
 * about detected MCP servers and agents.
 *
 * Used by `opena2a detect --registry` to annotate scan results with trust scores,
 * community scan counts, and verification status from the public registry.
 */

import { validateRegistryUrl } from './validate-registry-url.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RegistryEnrichment {
  name: string;
  packageType: string;
  trustScore: number;
  trustLevel: number;
  verdict: string;
  communityScans: number;
  verified: boolean;
  scanStatus: string;
}

export interface RegistryBatchResult {
  packageId: string;
  name: string;
  packageType: string;
  trustLevel: number;
  trustScore: number;
  verdict: string;
  confidence: number;
  scanStatus: string;
  communityScans: number;
}

export interface RegistryBatchResponse {
  queriedAt: string;
  results: RegistryBatchResult[];
  total: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REGISTRY_TIMEOUT_MS = 5000;
const DEFAULT_REGISTRY_BASE = 'https://api.oa2a.org';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Enrich a list of assets with community trust data from the OpenA2A Registry.
 *
 * Uses the batch endpoint for efficiency. Handles errors gracefully -- if the
 * registry is unreachable, slow, or returns unexpected data, returns an empty
 * map instead of throwing.
 *
 * @param assets  Array of { name, type } to query (e.g. MCP server names)
 * @param registryBaseUrl  Base URL of the registry (no trailing slash)
 * @returns Map of "name:type" -> enrichment data
 */
export async function enrichFromRegistry(
  assets: { name: string; type: string }[],
  registryBaseUrl?: string,
): Promise<Map<string, RegistryEnrichment>> {
  const enrichments = new Map<string, RegistryEnrichment>();

  if (assets.length === 0) {
    return enrichments;
  }

  const baseUrl = (registryBaseUrl || DEFAULT_REGISTRY_BASE).replace(/\/+$/, '');
  validateRegistryUrl(baseUrl);
  const batchUrl = `${baseUrl}/api/v1/trust/batch`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REGISTRY_TIMEOUT_MS);

    const body = JSON.stringify({
      packages: assets.map((a) => ({ name: a.name, type: a.type })),
    });

    const response = await fetch(batchUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      return enrichments;
    }

    const data = (await response.json()) as RegistryBatchResponse;

    if (!data.results || !Array.isArray(data.results)) {
      return enrichments;
    }

    for (const result of data.results) {
      const key = `${result.name}:${result.packageType}`;
      enrichments.set(key, {
        name: result.name,
        packageType: result.packageType,
        trustScore: result.trustScore,
        trustLevel: result.trustLevel,
        verdict: result.verdict,
        communityScans: result.communityScans,
        verified: result.verdict === 'verified' || result.trustLevel >= 4,
        scanStatus: result.scanStatus,
      });
    }
  } catch {
    // Registry unreachable, timed out, or returned bad data -- skip enrichment
  }

  return enrichments;
}

/**
 * Format a trust score (0-1 float) as a human-readable "X/100" string.
 */
export function formatTrustScore(score: number): string {
  return `${Math.round(score * 100)}/100`;
}

/**
 * Build a concise trust label for text output.
 * Examples: "Trust: 92/100 | 45 community scans"
 *           "Trust: 50/100 | listed"
 *           "No registry data"
 */
export function formatTrustLabel(enrichment: RegistryEnrichment | undefined): string {
  if (!enrichment) {
    return 'No registry data';
  }

  const score = formatTrustScore(enrichment.trustScore);
  const parts = [`Trust: ${score}`];

  if (enrichment.communityScans > 0) {
    parts.push(`${enrichment.communityScans} community scan${enrichment.communityScans !== 1 ? 's' : ''}`);
  } else if (enrichment.verdict) {
    parts.push(enrichment.verdict);
  }

  return parts.join(' | ');
}
