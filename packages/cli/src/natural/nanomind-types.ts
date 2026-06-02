/**
 * Wire-format types for the @nanomind/daemon HTTP classifier.
 *
 * Mirrors the frozen v0.3.0 wire contract shipped by
 * @nanomind/daemon, ported here so opena2a-cli does not take a hard
 * dependency on the daemon package. The adapter in
 * ./nanomind-classifier.ts speaks this contract over plain HTTP.
 *
 * Source of truth for the upstream shape: the aicomply 2.0 reference
 * adapter at aicomply/src/classifier/guard-client/types.ts. Keep this
 * file in sync when the daemon bumps its major version.
 */

/**
 * Canonical attack-class enum the daemon emits on every response. The
 * empty string is the always-emitted default for benign / no-block;
 * the four non-empty values come from the production classifier
 * (nanomind-security-classifier v0.5.0, Mamba TME ONNX).
 *
 * Block contract per AIM FGA Step 5:
 *   attackClass !== '' AND confidence > 0.8
 */
export type NanoMindAttackClass =
  | ''
  | 'exfiltration_pattern'
  | 'prompt_injection'
  | 'tool_misuse'
  | 'data_extraction';

/**
 * POST body sent to `/v1/infer` on the daemon.
 *
 * `intent` is metadata only; the engine classifies `input` regardless
 * of which intent string is passed. INTENT_CHECK is the convention.
 */
export interface NanoMindInferRequest {
  intent: string;
  input: string;
  context?: {
    agentId?: string;
    driftScore?: number;
    declaredPurpose?: string;
  };
  priority?: 'high' | 'medium' | 'low';
}

/**
 * Success-path body returned by `POST /v1/infer`.
 *
 * `attackClass` is always a string (the daemon contract forbids
 * undefined). `confidence` is in [0.0, 1.0]. `evidence` and
 * `remediation` are advisory and may carry attacker-influenced bytes;
 * consumers MUST NOT echo them into audit logs or user-facing strings.
 */
export interface NanoMindInferResponse {
  intent: string;
  result: string;
  confidence: number;
  attackClass: NanoMindAttackClass;
  evidence?: string;
  remediation?: string;
  latencyMs: number;
  modelVersion: string;
}

/**
 * Classification result the adapter returns to callers.
 *
 * `blocked === true` only when the daemon emits a non-empty
 * attackClass with confidence above the AIM FGA block threshold
 * (> 0.8). Below the threshold the daemon is hedging; classifications
 * stay non-blocked but the attackClass is preserved so callers can
 * route soft signals into telemetry.
 *
 * The daemon's `evidence` and `remediation` fields are deliberately
 * absent from this type. They are an attack surface (the input is
 * reflected through some daemon paths) and must never reach
 * downstream operator dashboards or audit trails.
 */
export interface NanoMindClassification {
  blocked: boolean;
  attackClass: NanoMindAttackClass;
  confidence: number;
  modelVersion: string;
  latencyMs: number;
}

export interface NanoMindClassifierOptions {
  /**
   * Base URL the daemon is reachable at. Defaults to
   * `http://127.0.0.1:47200`. The `MOCK_NANOMIND_URL` env var
   * overrides the default for tests and local development.
   */
  baseUrl?: string;
  /**
   * Per-call timeout in milliseconds. Beyond this the request is
   * aborted and the adapter returns null. Defaults to 5000.
   */
  timeoutMs?: number;
  /**
   * Optional caller-supplied agent identifier surfaced as
   * `context.agentId` on the daemon request. Has no effect on
   * classification today.
   */
  agentId?: string;
}
