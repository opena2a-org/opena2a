/**
 * Map the registry's scanStatus vocabulary onto the meter-gate tri-state
 * consumed by renderCheckBlock in `@opena2a/cli-ui@0.3.0`:
 *
 *   - `"completed"` — render the Security meter with the numeric score.
 *   - `"warnings"`  — render the meter with a warnings chrome.
 *   - `undefined`   — suppress the meter (F6: a number implies measurement;
 *     don't show one for pending/failed/unknown states).
 */
export function mapScanStatusForMeter(status?: string): "completed" | "warnings" | undefined {
  if (!status) return undefined;
  const normalized = status.toLowerCase().trim();
  if (normalized === "" || normalized === "pending" || normalized === "not_applicable") return undefined;
  if (normalized === "error" || normalized === "failed") return undefined;
  if (normalized === "warnings" || normalized === "warning") return "warnings";
  if (normalized === "complete" || normalized === "completed" || normalized === "passed") return "completed";
  return undefined;
}
