import chalk from "chalk";
import type { TelemetryStatusLike } from "./version-line.js";

export type TelemetryAction = "on" | "off" | "status" | undefined;

export interface TelemetryCommandInput {
  /** Tool name — only used in the printed output. */
  tool: string;
  /** Returns the current telemetry status. Typically `tele.status`. */
  getStatus: () => TelemetryStatusLike & { configPath: string; installId: string };
  /** Persists the new opt-out state. Typically `tele.setOptOut`. */
  setOptOut: (enabled: boolean) => unknown;
}

/**
 * Run a `<tool> telemetry [on|off|status]` subcommand.
 *
 * Returns the string to print. CLIs wire this in three lines:
 *
 *   program.command("telemetry [action]").action((action) => {
 *     console.log(runTelemetryCommand(action, { tool: "dvaa", getStatus: tele.status, setOptOut: tele.setOptOut }));
 *   });
 *
 * Default action (no args) is `status`.
 */
export function runTelemetryCommand(
  action: TelemetryAction,
  input: TelemetryCommandInput,
): string {
  switch (action) {
    case "on":
      input.setOptOut(true);
      return renderStatus("enabled", input);
    case "off":
      input.setOptOut(false);
      return renderStatus("disabled", input);
    case "status":
    case undefined:
      return renderStatus("current", input);
    default:
      return chalk.red(
        `Unknown action '${action}'. Try '${input.tool} telemetry [on|off|status]'.`,
      );
  }
}

function renderStatus(
  framing: "enabled" | "disabled" | "current",
  input: TelemetryCommandInput,
): string {
  const status = input.getStatus();
  const stateWord = status.enabled ? chalk.green("on") : chalk.dim("off");
  const header =
    framing === "enabled"
      ? chalk.green(`Telemetry enabled for ${input.tool}.`)
      : framing === "disabled"
        ? chalk.dim(`Telemetry disabled for ${input.tool}.`)
        : chalk.bold(`${input.tool} telemetry`);
  const lines = [
    header,
    `  state:       ${stateWord}`,
    `  install_id:  ${chalk.dim(status.installId)}`,
    `  config:      ${chalk.dim(status.configPath)}`,
    `  policy:      ${chalk.cyan(status.policyURL)}`,
  ];
  if (framing === "current") {
    lines.push(
      "",
      chalk.dim(`  toggle: '${input.tool} telemetry off'  or  OPENA2A_TELEMETRY=off`),
    );
  }
  return lines.join("\n");
}
