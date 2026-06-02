/**
 * HTTP adapter for the @nanomind/daemon classifier (NLM tier).
 *
 * The daemon serves classification over HTTP on `127.0.0.1:47200` by
 * default. This module:
 *
 *   - POSTs `{ intent, input }` to `/v1/infer`.
 *   - Strictly validates every field on the response per the frozen
 *     v0.3.0 wire contract; any malformed payload is rejected.
 *   - Maps `attackClass` and `confidence` into a simple
 *     `NanoMindClassification` shape per AIM FGA Step 5:
 *       attackClass !== '' AND confidence > 0.8 -> blocked
 *       (everything else -> not blocked)
 *
 * On any error (network failure, non-2xx HTTP status, malformed JSON,
 * schema violation, request timeout) the adapter returns `null` so
 * callers can silently fall back. The daemon is treated as a
 * defense-in-depth layer; its absence MUST NEVER cause a request to
 * fail.
 *
 * Trust boundary: the daemon is a separate process and its responses
 * are an attack surface. The `evidence` and `remediation` strings on
 * the wire MAY contain attacker-influenced bytes (ANSI escapes,
 * log-injection newlines, shell payloads). This adapter NEVER
 * surfaces those fields to callers; only the canonical attackClass
 * enum, confidence, modelVersion, and latencyMs are returned.
 *
 * Ported from the aicomply 2.0 reference adapter at
 * aicomply/src/classifier/guard-client/nanomind-adapter.ts.
 */

import type {
  NanoMindAttackClass,
  NanoMindClassification,
  NanoMindClassifierOptions,
  NanoMindInferRequest,
  NanoMindInferResponse,
} from './nanomind-types.js';

const NON_EMPTY_ATTACK_CLASSES: ReadonlySet<NanoMindAttackClass> = new Set([
  'exfiltration_pattern',
  'prompt_injection',
  'tool_misuse',
  'data_extraction',
]);

const BLOCK_CONFIDENCE_THRESHOLD = 0.8;

export const DEFAULT_NANOMIND_DAEMON_URL = 'http://127.0.0.1:47200';
export const DEFAULT_NANOMIND_TIMEOUT_MS = 5000;
export const NANOMIND_INFER_ENDPOINT = '/v1/infer';
export const NANOMIND_HEALTH_ENDPOINT = '/health';
export const NANOMIND_DEFAULT_INTENT = 'INTENT_CHECK';

/**
 * Cap on accepted response-body size. The classification response is a
 * small JSON object (sub-kilobyte in practice); anything beyond 1 MiB is
 * either a misconfigured daemon or a hostile process bound to the
 * loopback port trying to OOM the host. Reading is bounded so a
 * compromised daemon cannot exhaust caller memory.
 */
export const MAX_NANOMIND_RESPONSE_BYTES = 1024 * 1024;

/**
 * Defense against SSRF / accidental misconfiguration via the
 * `baseUrl` option or the `MOCK_NANOMIND_URL` env var. The daemon
 * binds to the loopback interface and the wire contract is local-only;
 * a non-loopback URL almost certainly reflects a typo (e.g.
 * `http://127.0.0.0:47200`) or an attempt to redirect classifier
 * input to an external endpoint. Either case is rejected upstream of
 * the request so user input never leaves the host.
 *
 * Allowed: http(s) scheme, host == `127.0.0.1`, `localhost`, `::1`, or
 * `[::1]` (with bracketed-IPv6 normalization). Any other shape is
 * rejected; callers see the same silent-fallback `null` they would
 * see from a daemon-unreachable error.
 */
export function isLocalhostHttpUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  const host = parsed.hostname;
  return host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]';
}

function resolveBaseUrl(override?: string): string {
  return (
    override ??
    process.env.MOCK_NANOMIND_URL ??
    DEFAULT_NANOMIND_DAEMON_URL
  );
}

function validateInferResponse(raw: unknown): NanoMindInferResponse | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const r = raw as Record<string, unknown>;

  if (typeof r.intent !== 'string') return null;
  if (typeof r.result !== 'string') return null;
  if (typeof r.confidence !== 'number') return null;
  if (r.confidence < 0 || r.confidence > 1) return null;
  if (typeof r.attackClass !== 'string') return null;
  if (
    r.attackClass !== '' &&
    !NON_EMPTY_ATTACK_CLASSES.has(r.attackClass as NanoMindAttackClass)
  ) {
    return null;
  }
  if (typeof r.latencyMs !== 'number' || r.latencyMs < 0) return null;
  if (typeof r.modelVersion !== 'string' || r.modelVersion.length === 0) return null;
  if (r.evidence !== undefined && typeof r.evidence !== 'string') return null;
  if (r.remediation !== undefined && typeof r.remediation !== 'string') return null;

  return r as unknown as NanoMindInferResponse;
}

/**
 * Map a validated daemon response into the public classification
 * shape. The daemon's `evidence` and `remediation` strings are
 * intentionally dropped here; see the trust-boundary note at the top
 * of this file.
 */
export function mapInferResponseToClassification(
  response: NanoMindInferResponse,
): NanoMindClassification {
  const isBenign = response.attackClass === '';
  const aboveThreshold = response.confidence > BLOCK_CONFIDENCE_THRESHOLD;
  const blocked = !isBenign && aboveThreshold;

  return {
    blocked,
    attackClass: response.attackClass,
    confidence: response.confidence,
    modelVersion: response.modelVersion,
    latencyMs: response.latencyMs,
  };
}

/**
 * Run one classification call against the @nanomind/daemon. Returns
 * a `NanoMindClassification` on a clean round-trip, `null` on any
 * failure (network, non-2xx, malformed payload, timeout). Callers
 * silently proceed without Guard when this returns null.
 */
export async function classifyWithNanoMindDaemon(
  content: string,
  options: NanoMindClassifierOptions = {},
): Promise<NanoMindClassification | null> {
  const baseUrl = resolveBaseUrl(options.baseUrl);
  if (!isLocalhostHttpUrl(baseUrl)) return null;
  const timeoutMs = options.timeoutMs ?? DEFAULT_NANOMIND_TIMEOUT_MS;
  const url = baseUrl.replace(/\/+$/, '') + NANOMIND_INFER_ENDPOINT;

  if (content.trim().length === 0) return null;

  const requestBody: NanoMindInferRequest = {
    intent: NANOMIND_DEFAULT_INTENT,
    input: content,
    ...(options.agentId !== undefined ? { context: { agentId: options.agentId } } : {}),
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    });

    if (!res.ok) return null;

    // Fast-path: trust an honest Content-Length declaration. A
    // hostile daemon can lie and we still bound the read below.
    const declaredLength = res.headers.get('content-length');
    if (declaredLength !== null) {
      const n = Number.parseInt(declaredLength, 10);
      if (Number.isFinite(n) && n > MAX_NANOMIND_RESPONSE_BYTES) return null;
    }

    let text: string;
    try {
      text = await res.text();
    } catch {
      return null;
    }
    if (text.length > MAX_NANOMIND_RESPONSE_BYTES) return null;

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return null;
    }

    const validated = validateInferResponse(parsed);
    if (validated === null) return null;

    return mapInferResponseToClassification(validated);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Liveness probe against the daemon's health endpoint. Returns true
 * only when the daemon responds 2xx within the configured short
 * timeout. Use this before declaring the classifier "armed" in
 * operator-facing status output. Do NOT gate `classifyWithNanoMindDaemon`
 * on this; the per-call timeout is the authoritative health check.
 */
export async function isNanoMindDaemonAvailable(
  options: Pick<NanoMindClassifierOptions, 'baseUrl' | 'timeoutMs'> = {},
): Promise<boolean> {
  const baseUrl = resolveBaseUrl(options.baseUrl);
  if (!isLocalhostHttpUrl(baseUrl)) return false;
  const timeoutMs = Math.min(options.timeoutMs ?? 200, DEFAULT_NANOMIND_TIMEOUT_MS);
  const url = baseUrl.replace(/\/+$/, '') + NANOMIND_HEALTH_ENDPOINT;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method: 'GET', signal: controller.signal });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}
