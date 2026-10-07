/**
 * The telemetry line of `opena2a --help`.
 *
 * It states the effective telemetry state, the same state `opena2a --version`
 * and `opena2a telemetry status` report. A fixed "on" line contradicted both
 * whenever telemetry was off.
 */

export interface TelemetryHelpStatus {
  enabled: boolean;
  suppressedBy?: 'ci' | 'do-not-track' | 'env-opt-out' | 'test-runner' | 'ephemeral-home';
}

const SUPPRESSION_LABEL: Record<NonNullable<TelemetryHelpStatus['suppressedBy']>, string> = {
  ci: 'CI environment detected',
  'do-not-track': 'DO_NOT_TRACK is set',
  'env-opt-out': 'OPENA2A_TELEMETRY=off is set',
  'test-runner': 'test runner detected',
  'ephemeral-home': 'temporary home directory detected',
};

export function telemetryHelpLine(status: TelemetryHelpStatus): string {
  if (status.enabled) {
    return 'Usage telemetry is on and each event carries a persistent install ID. Disable: OPENA2A_TELEMETRY=off';
  }
  const reason = status.suppressedBy ? ` (${SUPPRESSION_LABEL[status.suppressedBy]})` : '';
  return `Usage telemetry is off${reason}: no events are sent and no install ID is kept. Details: opena2a telemetry status`;
}
