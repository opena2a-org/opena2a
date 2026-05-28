import chalk from "chalk";
import type { TelemetryStatusLike } from "./version-line.js";

export type TelemetryAction = "on" | "off" | "status" | "--help" | "-h" | undefined;

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
    case "--help":
    case "-h":
      return renderHelp(input);
    default:
      return chalk.red(
        `Unknown action '${action}'. Try '${input.tool} telemetry [on|off|status]'.`,
      );
  }
}

function renderHelp(input: TelemetryCommandInput): string {
  const tool = input.tool;
  return [
    chalk.bold(`${tool} telemetry [on|off|status]`),
    "",
    `Inspect or toggle the persisted anonymous-telemetry opt-out for ${tool}.`,
    "Default action (no args) is 'status'.",
    "",
    chalk.bold("Actions:"),
    `  on        Enable telemetry persistently for ${tool}.`,
    `  off       Disable telemetry persistently for ${tool}.`,
    `  status    Show current state, install_id, config file, and policy URL.`,
    `  --help    Show this message.`,
    "",
    chalk.bold("Per-invocation override (does not persist):"),
    `  OPENA2A_TELEMETRY=off ${tool} <cmd>`,
    "",
    chalk.bold("Debug:"),
    `  OPENA2A_TELEMETRY_DEBUG=print ${tool} <cmd>    Print payloads to stderr.`,
  ].join("\n");
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
    // Suggest the OPPOSITE of the current state — telling someone whose
    // telemetry is already off how to "turn it off" is useless. The
    // env-var hint mirrors the same flip.
    const nextAction = status.enabled ? "off" : "on";
    const envOverride = status.enabled ? "OPENA2A_TELEMETRY=off" : "OPENA2A_TELEMETRY=on";
    lines.push(
      "",
      chalk.dim(`  toggle: '${input.tool} telemetry ${nextAction}'  or  ${envOverride}`),
    );
  }
  return lines.join("\n");
}
