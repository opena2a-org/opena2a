/**
 * Drift liveness verification.
 *
 * After pattern matching detects a credential (e.g., DRIFT-001 Google API key),
 * this module performs an actual API call to verify whether the credential has
 * drifted capabilities (e.g., Gemini access on a Maps key).
 *
 * Liveness checks are opt-in, non-blocking, and timeout after 5 seconds.
 */

import * as crypto from 'crypto';
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

// --- AWS SigV4 Helpers (minimal, zero-dependency implementation) ---

function hmacSha256(key: Buffer | string, data: string): Buffer {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function sha256Hex(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function getSignatureKey(
  secretKey: string,
  dateStamp: string,
  region: string,
  service: string,
): Buffer {
  const kDate = hmacSha256('AWS4' + secretKey, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  return hmacSha256(kService, 'aws4_request');
}

function signAwsRequest(params: {
  method: string;
  host: string;
  path: string;
  body: string;
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  service: string;
}): Record<string, string> {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const dateStamp = amzDate.slice(0, 8);

  const payloadHash = sha256Hex(params.body);

  const canonicalHeaders =
    `host:${params.host}\n` +
    `x-amz-date:${amzDate}\n`;

  const signedHeaders = 'host;x-amz-date';

  const canonicalRequest = [
    params.method,
    params.path,
    '', // query string (empty for POST)
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const credentialScope = `${dateStamp}/${params.region}/${params.service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  const signingKey = getSignatureKey(
    params.secretAccessKey,
    dateStamp,
    params.region,
    params.service,
  );

  const signature = crypto
    .createHmac('sha256', signingKey)
    .update(stringToSign)
    .digest('hex');

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${params.accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    'Host': params.host,
    'X-Amz-Date': amzDate,
    'Authorization': authorization,
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'opena2a-drift-check/1.0',
  };
}

// --- AWS STS and Bedrock API calls ---

async function callStsGetCallerIdentity(
  accessKeyId: string,
  secretAccessKey: string,
  signal: AbortSignal,
): Promise<{ live: boolean; detail: string; error?: string }> {
  const host = 'sts.amazonaws.com';
  const body = 'Action=GetCallerIdentity&Version=2011-06-15';

  const headers = signAwsRequest({
    method: 'POST',
    host,
    path: '/',
    body,
    accessKeyId,
    secretAccessKey,
    region: 'us-east-1',
    service: 'sts',
  });

  const response = await fetch(`https://${host}/`, {
    method: 'POST',
    headers,
    body,
    signal,
  });

  if (response.status === 200) {
    const text = await response.text();
    // Extract account ID from XML response
    const accountMatch = text.match(/<Account>(\d+)<\/Account>/);
    const arnMatch = text.match(/<Arn>([^<]+)<\/Arn>/);
    const account = accountMatch?.[1] ?? 'unknown';
    const arn = arnMatch?.[1] ?? 'unknown';
    return { live: true, detail: `Account ${account}, ARN: ${arn}` };
  }

  if (response.status === 403) {
    return { live: false, detail: 'AWS key is invalid or expired' };
  }

  return {
    live: false,
    detail: `STS returned unexpected status ${response.status}`,
  };
}

async function callBedrockListModels(
  accessKeyId: string,
  secretAccessKey: string,
  signal: AbortSignal,
): Promise<{ hasAccess: boolean; detail: string }> {
  const region = 'us-east-1';
  const host = `bedrock.${region}.amazonaws.com`;
  const path = '/foundation-models';

  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const dateStamp = amzDate.slice(0, 8);

  const payloadHash = sha256Hex('');

  const canonicalHeaders =
    `host:${host}\n` +
    `x-amz-date:${amzDate}\n`;

  const signedHeaders = 'host;x-amz-date';

  const canonicalRequest = [
    'GET',
    path,
    '', // query string
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const credentialScope = `${dateStamp}/${region}/bedrock/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  const signingKey = getSignatureKey(secretAccessKey, dateStamp, region, 'bedrock');
  const signature = crypto
    .createHmac('sha256', signingKey)
    .update(stringToSign)
    .digest('hex');

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const response = await fetch(`https://${host}${path}`, {
    method: 'GET',
    headers: {
      'Host': host,
      'X-Amz-Date': amzDate,
      'Authorization': authorization,
      'User-Agent': 'opena2a-drift-check/1.0',
    },
    signal,
  });

  if (response.status === 200) {
    let modelCount = 0;
    try {
      const body = await response.json() as { modelSummaries?: unknown[] };
      modelCount = body.modelSummaries?.length ?? 0;
    } catch {
      // Response parsing failed but 200 confirms access
    }
    return {
      hasAccess: true,
      detail: modelCount > 0
        ? `can access ${modelCount} foundation model(s)`
        : 'Bedrock API is accessible',
    };
  }

  return { hasAccess: false, detail: `Bedrock returned ${response.status}` };
}

// --- Secret key proximity search ---

/**
 * Try to find an AWS secret access key near an access key ID in the same file.
 * Searches within 5 lines of the access key's location.
 */
function findSecretKeyNearAccessKey(match: CredentialMatch): string | undefined {
  try {
    const fs = require('fs');
    const content = fs.readFileSync(match.filePath, 'utf-8');
    const lines = content.split('\n');
    const startLine = Math.max(0, match.line - 6);
    const endLine = Math.min(lines.length, match.line + 5);
    const region = lines.slice(startLine, endLine).join('\n');

    // AWS secret access keys are 40 chars of base64-like characters
    const secretKeyPattern = /(?:secret[_-]?(?:access)?[_-]?key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i;

    // Try the labeled pattern first
    const labeled = secretKeyPattern.exec(region);
    if (labeled) return labeled[1];

    // Fallback: look for 40-char base64 strings that aren't the access key itself
    const envPattern = /[A-Za-z0-9/+=]{40}/g;
    const allMatches = region.match(envPattern);
    if (allMatches) {
      for (const m of allMatches) {
        if (m !== match.value && /[a-z]/.test(m) && /[A-Z]/.test(m)) {
          return m;
        }
      }
    }

    return undefined;
  } catch {
    return undefined;
  }
}

// --- AWS Bedrock drift verification ---

/**
 * Verify whether an AWS access key is live and has Bedrock access.
 *
 * Step 1: STS GetCallerIdentity -- confirms key is live (always works, zero permissions needed).
 * Step 2: If live, try ListFoundationModels to check Bedrock access.
 *
 * AWS SigV4 signing is done manually -- no SDK dependency.
 * Requires the secret key to be found alongside the access key.
 */
export async function verifyBedrockAccess(
  accessKeyId: string,
  secretAccessKey?: string,
): Promise<LivenessResult> {
  const result: LivenessResult = {
    findingId: 'DRIFT-002',
    checked: true,
    live: false,
    originalSeverity: 'high',
    escalatedSeverity: 'high',
    detail: '',
  };

  if (!secretAccessKey) {
    result.checked = false;
    result.detail = 'Secret access key not found alongside access key ID -- cannot verify liveness';
    return result;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), LIVENESS_TIMEOUT_MS);

    // Step 1: STS GetCallerIdentity (works with any valid key, zero permissions needed)
    const stsResult = await callStsGetCallerIdentity(
      accessKeyId,
      secretAccessKey,
      controller.signal,
    );

    clearTimeout(timeout);

    if (!stsResult.live) {
      result.detail = stsResult.detail;
      result.error = stsResult.error;
      return result;
    }

    // Key is live
    result.live = true;
    result.escalatedSeverity = 'critical';
    result.detail = `AWS key is live (${stsResult.detail})`;

    // Step 2: Try Bedrock ListFoundationModels
    const controller2 = new AbortController();
    const timeout2 = setTimeout(() => controller2.abort(), LIVENESS_TIMEOUT_MS);

    try {
      const bedrockResult = await callBedrockListModels(
        accessKeyId,
        secretAccessKey,
        controller2.signal,
      );
      clearTimeout(timeout2);

      if (bedrockResult.hasAccess) {
        result.detail += `. Bedrock access confirmed: ${bedrockResult.detail}`;
      } else {
        result.detail += '. No Bedrock access detected (key is still live and exploitable)';
      }
    } catch {
      clearTimeout(timeout2);
      result.detail += '. Bedrock check inconclusive (key is still live and exploitable)';
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
        case 'DRIFT-002': {
          const secretKey = findSecretKeyNearAccessKey(match);
          result = await verifyBedrockAccess(match.value, secretKey);
          break;
        }
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
