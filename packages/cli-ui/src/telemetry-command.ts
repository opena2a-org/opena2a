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
  // `telemetry on` under automatic suppression persists the preference but
  // does not change the effective state. Claiming "enabled" above a
  // `state: off` line is a straight contradiction — report what the write
  // actually achieved.
  const header =
    framing === "enabled"
      ? status.enabled
        ? chalk.green(`Telemetry enabled for ${input.tool}.`)
        : chalk.dim(`Preference saved, but telemetry stays off for ${input.tool} here.`)
      : framing === "disabled"
        ? chalk.dim(`Telemetry disabled for ${input.tool}.`)
        : chalk.bold(`${input.tool} telemetry`);
  const lines = [
    header,
    `  state:       ${stateWord}${suppressionNote(status.suppressedBy)}`,
    `  install_id:  ${chalk.dim(status.installId)}`,
    `  config:      ${chalk.dim(status.configPath)}`,
    `  policy:      ${chalk.cyan(status.policyURL)}`,
  ];
  if (status.suppressedBy) {
    // Suppression re-applies on every load, so `telemetry on` would write
    // enabled=true and change nothing observable. Say what is actually
    // happening and give the remedy that does work, rather than sending
    // someone round a loop that always lands back on "off".
    lines.push(
      "",
      chalk.dim(`  ${suppressionExplanation(status.suppressedBy)}`),
      chalk.dim(`  ${suppressionRemedy(status.suppressedBy, input.tool)}`),
    );
  } else if (framing === "current") {
    // Suggest the OPPOSITE of the current state — telling someone whose
    // telemetry is already off how to "turn it off" is useless.
    //
    // The env-var hint does NOT mirror that flip, because the two
    // directions are not symmetric. OPENA2A_TELEMETRY=off disables from
    // any state, so it is a valid partner to `telemetry off`. But
    // OPENA2A_TELEMETRY=on cannot re-enable a persisted opt-out —
    // precedence rule 2 says the config file wins — and this hint only
    // ever prints for an off-state that came from that file. Offering it
    // sent the user round a loop landing on an identical, unexplained
    // "off". `telemetry on` alone is the remedy that works here.
    if (status.enabled) {
      lines.push(
        "",
        chalk.dim(`  toggle: '${input.tool} telemetry off'  or  OPENA2A_TELEMETRY=off`),
      );
    } else {
      lines.push("", chalk.dim(`  toggle: '${input.tool} telemetry on'`));
    }
  }
  return lines.join("\n");
}

type SuppressionReason = NonNullable<TelemetryStatusLike["suppressedBy"]>;

const SUPPRESSION_LABEL: Record<SuppressionReason, string> = {
  ci: "CI environment detected",
  "do-not-track": "DO_NOT_TRACK is set",
  "env-opt-out": "OPENA2A_TELEMETRY=off is set",
};

// CI is an environmental fact the user did not choose, so say so. The other
// two ARE the user's own doing — telling them "you did not turn it off"
// would be wrong.
const SUPPRESSION_EXPLANATION: Record<SuppressionReason, string> = {
  ci: "Telemetry is suppressed automatically in CI — you did not turn it off.",
  "do-not-track": "DO_NOT_TRACK is set in this environment, so telemetry stays off.",
  "env-opt-out": "OPENA2A_TELEMETRY=off is set in this environment, which overrides the saved preference.",
};

// Each remedy must actually work for its reason. OPENA2A_TELEMETRY=on does
// not override DO_NOT_TRACK, and no `telemetry on` survives an env opt-out —
// offering either in the wrong place is how the dead ends got here.
function suppressionRemedy(reason: SuppressionReason, tool: string): string {
  switch (reason) {
    case "ci":
      return `override: OPENA2A_TELEMETRY=on ${tool} <cmd>`;
    case "do-not-track":
      return "to re-enable: unset DO_NOT_TRACK";
    case "env-opt-out":
      return "to re-enable: unset OPENA2A_TELEMETRY (or set it to 'on')";
  }
}

function suppressionNote(reason: SuppressionReason | undefined): string {
  if (!reason) return "";
  return chalk.dim(` (${SUPPRESSION_LABEL[reason]})`);
}

function suppressionExplanation(reason: SuppressionReason): string {
  return SUPPRESSION_EXPLANATION[reason];
}
