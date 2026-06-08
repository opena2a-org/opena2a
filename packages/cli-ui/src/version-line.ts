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
  const tail = telemetryDisclosure(input.telemetry);
  return tail ? `${head}\n${tail}` : head;
}

/**
 * Stream-split variant of {@link versionLine}.
 *
 * Returns the bare version on `stdout` and the telemetry disclosure on
 * `stderr` (or `null` when no telemetry status is supplied). Wire it so a
 * script doing `tool --version` (captures stdout) gets a clean, single-line
 * version string, while the privacy disclosure still prints to the terminal
 * via stderr — it remains a disclosure surface, just off the parseable stream.
 *
 *   const v = versionLineParts({ tool, version, telemetry: tele.status() });
 *   program.option("-v, --version", "Output the version number");
 *   program.on("option:version", () => {
 *     process.stdout.write(v.stdout + "\n");
 *     if (v.stderr) process.stderr.write(v.stderr + "\n");
 *     process.exit(0);
 *   });
 *
 * Use the manual `option:version` handler rather than Commander's `.version()`
 * so the two streams stay separate and ordering is deterministic — Commander's
 * built-in handler writes everything to stdout and exits.
 */
export function versionLineParts(input: VersionLineInput): {
  stdout: string;
  stderr: string | null;
} {
  return {
    stdout: `${input.tool} ${input.version}`,
    stderr: telemetryDisclosure(input.telemetry),
  };
}

/** The "Telemetry: on/off (opt-out: …)" disclosure line, or null when no status. */
function telemetryDisclosure(telemetry?: TelemetryStatusLike): string | null {
  if (!telemetry) return null;
  const state = telemetry.enabled ? chalk.green("on") : chalk.dim("off");
  const policy = telemetry.policyURL.replace(/^https?:\/\//, "");
  return chalk.dim(
    `Telemetry: ${state}${chalk.dim(
      ` (opt-out: OPENA2A_TELEMETRY=off  •  details: ${policy})`,
    )}`,
  );
}
