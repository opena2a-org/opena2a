/**
 * Drift liveness verification.
 *
 * After pattern matching detects a credential (e.g., DRIFT-001 Google API key),
 * this module performs an actual API call to verify whether the credential has
 * drifted capabilities (e.g., Gemini access on a Maps key).
 *
 * Liveness checks are opt-in, non-blocking, and timeout after 5 seconds.
 */

import type { CredentialMatch } from './credential-patterns.js';

// --- Types ---

export interface LivenessResult {
  /** Finding ID (e.g., "DRIFT-001") */
  findingId: string;
  /** Whether liveness verification was attempted */
  checked: boolean;
  /** Whether the drifted capability is confirmed live */
  live: boolean;
  /** Original severity before verification */
  originalSeverity: string;
  /** Escalated severity (if live) */
  escalatedSeverity: string;
  /** Human-readable detail about the verification result */
  detail: string;
  /** Error message if the check failed */
  error?: string;
}

// --- Constants ---

const LIVENESS_TIMEOUT_MS = 5_000;

const GEMINI_MODELS_ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/models';

// --- Verification functions ---

/**
 * Verify whether a Google API key has active Gemini access by calling
 * the Generative Language API's models endpoint.
 *
 * - 200: Key has Gemini access (drift confirmed)
 * - 403/401/400: No Gemini access or key invalid
 * - Network error: Inconclusive
 */
export async function verifyGeminiAccess(apiKey: string): Promise<LivenessResult> {
  const result: LivenessResult = {
    findingId: 'DRIFT-001',
    checked: true,
    live: false,
    originalSeverity: 'high',
    escalatedSeverity: 'high',
    detail: '',
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), LIVENESS_TIMEOUT_MS);

    const url = `${GEMINI_MODELS_ENDPOINT}?key=${apiKey}`;
    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'opena2a-drift-check/1.0',
      },
    });

    clearTimeout(timeout);

    if (response.status === 200) {
      let modelCount = 0;
      try {
        const body = await response.json() as { models?: unknown[] };
        modelCount = body.models?.length ?? 0;
      } catch {
        // Response parsing failed but 200 confirms access
      }

      result.live = true;
      result.escalatedSeverity = 'critical';
      result.detail = modelCount > 0
        ? `Gemini access confirmed: key can reach ${modelCount} model(s) via Generative Language API`
        : 'Gemini access confirmed: key authenticates to Generative Language API';
    } else if (response.status === 403 || response.status === 401) {
      result.detail = 'No Gemini access: key is restricted or Generative Language API is not enabled';
    } else if (response.status === 400) {
      result.detail = 'Key format valid but rejected by Google API (may be revoked or restricted)';
    } else {
      result.detail = `Unexpected response (HTTP ${response.status}): unable to confirm drift`;
    }
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') {
      result.detail = 'Liveness check timed out (5s) -- unable to confirm drift';
      result.error = 'timeout';
    } else {
      result.detail = 'Network error during liveness check -- unable to confirm drift';
      result.error = err instanceof Error ? err.message : String(err);
    }
  }

  return result;
}

/**
 * Run liveness verification on all DRIFT-prefixed credential matches.
 * Returns a map of credential value -> LivenessResult.
 *
 * Runs checks in parallel with a concurrency limit of 3.
 */
export async function verifyDriftFindings(
  matches: CredentialMatch[]
): Promise<Map<string, LivenessResult>> {
  const results = new Map<string, LivenessResult>();

  // Deduplicate: only check each unique key value once
  const seen = new Set<string>();
  const uniqueDriftMatches: CredentialMatch[] = [];

  for (const m of matches) {
    if (!m.findingId.startsWith('DRIFT-')) continue;
    if (seen.has(m.value)) continue;
    seen.add(m.value);
    uniqueDriftMatches.push(m);
  }

  if (uniqueDriftMatches.length === 0) return results;

  // Run verifications in parallel (max 3 concurrent)
  const CONCURRENCY = 3;
  for (let i = 0; i < uniqueDriftMatches.length; i += CONCURRENCY) {
    const chunk = uniqueDriftMatches.slice(i, i + CONCURRENCY);

    const promises = chunk.map(async (match) => {
      let result: LivenessResult;

      switch (match.findingId) {
        case 'DRIFT-001':
          result = await verifyGeminiAccess(match.value);
          break;
        default:
          result = {
            findingId: match.findingId,
            checked: false,
            live: false,
            originalSeverity: match.severity,
            escalatedSeverity: match.severity,
            detail: 'No liveness check available for this drift type',
          };
      }

      results.set(match.value, result);
    });

    await Promise.all(promises);
  }

  return results;
}

/**
 * Apply liveness results to credential matches: escalate severity
 * and update explanation text for confirmed drift.
 *
 * Returns new match objects (does not mutate originals).
 */
export function applyLivenessResults(
  matches: CredentialMatch[],
  livenessResults: Map<string, LivenessResult>
): CredentialMatch[] {
  return matches.map(match => {
    const result = livenessResults.get(match.value);
    if (!result) return match;

    if (result.live) {
      return {
        ...match,
        severity: result.escalatedSeverity,
        explanation: (match.explanation ?? '') +
          ` CONFIRMED: ${result.detail}`,
        businessImpact: (match.businessImpact ?? '') +
          ' Liveness verification confirmed the key has active Gemini access -- this is an active exposure, not theoretical.',
      };
    }

    // Not live but checked -- append verification note
    if (result.checked && !result.error) {
      return {
        ...match,
        explanation: (match.explanation ?? '') +
          ` Verification: ${result.detail}`,
      };
    }

    return match;
  });
}
