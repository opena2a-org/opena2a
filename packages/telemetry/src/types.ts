/**
 * Wire-format event sent to POST /api/v1/registry/telemetry/v1/event.
 *
 * Field names match the Registry handler's JSON binding (snake_case for
 * install_id, node_major, duration_ms — locked by the spec).
 */
export interface UsageEvent {
  tool: string;
  version: string;
  install_id: string;
  event: "install" | "start" | "command" | "error";
  name?: string;
  success?: boolean;
  duration_ms?: number;
  platform?: string;
  node_major?: number;
}

export interface InitOptions {
  /** Tool name. Lowercase, [a-z0-9_-], 1-64 chars (enforced by Registry). */
  tool: string;
  /** Tool version. ≤64 chars. */
  version: string;
}

export interface TrackFields {
  success?: boolean;
  durationMs?: number;
}

export interface Status {
  enabled: boolean;
  configPath: string;
  policyURL: string;
  installId: string;
}
