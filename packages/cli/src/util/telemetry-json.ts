/**
 * `opena2a telemetry [on|off|status] --json`: the same facts the text output
 * prints, as one JSON object (#469).
 *
 * Like the text output, it writes nothing for `status`: the status comes from
 * the SDK's `status()` and the contributor token from a peek that reads its
 * salt without creating it. `on` and `off` persist the preference first, as
 * they do without --json, and then report the state that results.
 *
 * An unknown action is reported as an `error` object and exits 0, as the
 * text output's message does.
 */

/** The fields of `@opena2a/telemetry`'s `status()` this output reports. */
export interface TelemetryStatusInput {
  enabled: boolean;
  configPath: string;
  policyURL: string;
  installId: string | null;
  suppressedBy?: string;
}

export interface TelemetryJsonInput {
  status: () => TelemetryStatusInput;
  setOptOut: (enabled: boolean) => unknown;
}

export interface TelemetryStatusJson {
  action: 'status' | 'on' | 'off';
  enabled: boolean;
  /** Why telemetry is off regardless of the saved preference, or null. */
  suppressedBy: string | null;
  /** Null while telemetry is off: no install ID is kept then. */
  installId: string | null;
  /** Null when no scan has been contributed from this machine yet, or the salt could not be read. */
  contributorToken: string | null;
  /** `present`, `none` (no salt yet) or `unavailable` (the salt could not be read). */
  contributorTokenState: 'present' | 'none' | 'unavailable';
  configPath: string;
  policyURL: string;
}

export interface TelemetryErrorJson {
  error: string;
  validActions: string[];
}

const VALID_ACTIONS = ['on', 'off', 'status'];

export function telemetryJson(
  action: string | undefined,
  tele: TelemetryJsonInput,
  peekContributorToken: () => string | null,
): TelemetryStatusJson | TelemetryErrorJson {
  if (action !== undefined && !VALID_ACTIONS.includes(action)) {
    return {
      error: `Unknown action '${action}'. Try 'opena2a telemetry [on|off|status]'.`,
      validActions: VALID_ACTIONS,
    };
  }
  if (action === 'on') tele.setOptOut(true);
  if (action === 'off') tele.setOptOut(false);
  const status = tele.status();
  let contributorToken: string | null = null;
  let contributorTokenState: TelemetryStatusJson['contributorTokenState'];
  try {
    contributorToken = peekContributorToken();
    contributorTokenState = contributorToken === null ? 'none' : 'present';
  } catch {
    contributorTokenState = 'unavailable';
  }
  return {
    action: (action ?? 'status') as TelemetryStatusJson['action'],
    enabled: status.enabled,
    suppressedBy: status.suppressedBy ?? null,
    installId: status.installId,
    contributorToken,
    contributorTokenState,
    configPath: status.configPath,
    policyURL: status.policyURL,
  };
}
