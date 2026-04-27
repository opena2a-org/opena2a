import chalk from "chalk";

/**
 * Status shape compatible with `@opena2a/telemetry`'s `status()` return.
 *
 * Declared structurally so cli-ui doesn't take a hard dep on the telemetry
 * package — consumers pass in `tele.status()`.
 */
export interface TelemetryStatusLike {
  enabled: boolean;
  policyURL: string;
}

export interface VersionLineInput {
  tool: string;
  version: string;
  /** Optional. When omitted, no telemetry line is appended. */
  telemetry?: TelemetryStatusLike;
}

/**
 * Build the multi-line `--version` output for a CLI.
 *
 * Returns:
 *   <tool> 0.8.1
 *   Telemetry: on (opt-out: OPENA2A_TELEMETRY=off  •  details: opena2a.org/telemetry)
 *
 * The telemetry line is only appended when `telemetry` is provided. Tools that
 * opted out of integrating telemetry can call `versionLine({ tool, version })`
 * with no second arg and get just the first line.
 */
export function versionLine(input: VersionLineInput): string {
  const head = `${input.tool} ${input.version}`;
  if (!input.telemetry) return head;
  const state = input.telemetry.enabled ? chalk.green("on") : chalk.dim("off");
  const policy = input.telemetry.policyURL.replace(/^https?:\/\//, "");
  const tail = chalk.dim(
    `Telemetry: ${state}${chalk.dim(
      ` (opt-out: OPENA2A_TELEMETRY=off  •  details: ${policy})`,
    )}`,
  );
  return `${head}\n${tail}`;
}
