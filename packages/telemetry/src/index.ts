/**
 * @opena2a/telemetry — Tier-1 anonymous usage telemetry SDK.
 *
 * No content collection. No first-run banner. Fire-and-forget HTTP.
 * See README.md and opena2a-registry/docs/telemetry-spec.md.
 */

import { platform as osPlatform } from "node:os";
import { loadConfig, setEnabled, configPaths, POLICY_URL } from "./config.js";
import { sendEvent } from "./sender.js";
import type { InitOptions, Status, TrackFields, UsageEvent } from "./types.js";

export { flush } from "./sender.js";

let session: { tool: string; version: string; installId: string; enabled: boolean } | null = null;

function nodeMajor(): number {
  return parseInt(process.versions.node.split(".")[0], 10);
}

/**
 * Initialize the SDK. Loads opt-out config, persists install_id.
 * Idempotent: calling twice with different tools is supported (the second
 * call rebinds the session — useful in test harnesses).
 */
export async function init(opts: InitOptions): Promise<void> {
  const { config } = loadConfig();
  session = {
    tool: opts.tool,
    version: opts.version,
    installId: config.installId,
    enabled: config.enabled,
  };
}

function buildEvent(event: UsageEvent["event"], extras: Partial<UsageEvent> = {}): UsageEvent | null {
  if (!session || !session.enabled) return null;
  return {
    tool: session.tool,
    version: session.version,
    install_id: session.installId,
    event,
    platform: osPlatform(),
    node_major: nodeMajor(),
    ...extras,
  };
}

export function start(): void {
  const evt = buildEvent("start");
  if (evt) void sendEvent(evt);
}

export async function track(name: string, fields: TrackFields = {}): Promise<void> {
  const evt = buildEvent("command", {
    name,
    success: fields.success,
    duration_ms: fields.durationMs,
  });
  if (evt) await sendEvent(evt);
}

export function error(name: string, code: string): void {
  const evt = buildEvent("error", { name, success: false });
  if (!evt) return;
  // The Registry schema doesn't have a free-form code field at v1. Encode
  // the failure code as the command name suffix so it groups in the dashboard
  // without needing a schema migration. Truncated to fit the 64-char `name` cap.
  evt.name = `${name}:${code}`.slice(0, 64);
  void sendEvent(evt);
}

export function status(): Status {
  if (!session) {
    const { config, paths } = loadConfig();
    return {
      enabled: config.enabled,
      configPath: paths.file,
      policyURL: POLICY_URL,
      installId: config.installId,
    };
  }
  return {
    enabled: session.enabled,
    configPath: configPaths().file,
    policyURL: POLICY_URL,
    installId: session.installId,
  };
}

/**
 * Persist enabled=true|false to the config file.
 * Used by `<tool> telemetry on|off` subcommands.
 */
export function setOptOut(enabled: boolean): Status {
  const cfg = setEnabled(enabled);
  if (session) session.enabled = enabled;
  return {
    enabled: cfg.enabled,
    configPath: configPaths().file,
    policyURL: POLICY_URL,
    installId: cfg.installId,
  };
}

/**
 * Translate a CLI's exit code into a `success` boolean for `track()`.
 *
 * Security-tool convention (npm audit, eslint, etc.): exit 0 means the
 * command found nothing wrong; exit 1 means the command worked and DID
 * find something (success at its job); exit >=2 means the command itself
 * failed (config error, crash, network failure, invalid input).
 *
 * Some tools use exit codes ≥ 2 for semantic outcomes that are NOT crashes
 * — for example `ai-trust check <not-found-pkg>` exits 2 to signal "I
 * checked, the package isn't in the registry," which is the command doing
 * its job, not a failure. The optional `semanticSuccessCodes` argument
 * lets each dispatcher declare its semantic-but-not-crash exit codes so
 * the dashboard signal reflects actual crash rate. Validation (range,
 * non-finite) always wins: an out-of-range value in `semanticSuccessCodes`
 * is treated as a programming bug and still returns false. See
 * [CHIEF-CSR-018] + [CHIEF-CPO-022] for the policy.
 *
 * @param exitCode - Process exit code (0-255 per POSIX) or undefined/null
 *   for processes that haven't set one (treated as success). Strings are
 *   accepted because Node 22+ widened `process.exitCode` to
 *   `string | number | null | undefined`; unparseable strings return false.
 * @param semanticSuccessCodes - Optional set of exit codes ≥ 2 that
 *   should be treated as success (semantic outcomes, not crashes). Codes
 *   outside the POSIX 0-255 range or that fail validation are still
 *   rejected regardless of this set.
 * @returns `true` if the exit code indicates success (0, 1, or any value
 *   listed in `semanticSuccessCodes`). `false` for any other failure code
 *   (≥ 2 and not listed), out-of-range value (< 0 or > 255), non-finite
 *   numbers, or unparseable strings.
 *
 * @example
 *   // POSIX-only (default): exit 2 is a failure
 *   tele.track(name, {
 *     success: tele.successFromExitCode(process.exitCode),
 *     durationMs: Date.now() - startedAt,
 *   });
 *
 * @example
 *   // ai-trust: exit 2 is a not-found outcome, not a crash
 *   tele.track(name, {
 *     success: tele.successFromExitCode(process.exitCode, [2]),
 *     durationMs: Date.now() - startedAt,
 *   });
 *
 * For commands that need a richer notion of success (network call failed
 * but exit code still 0, etc.), pass `success` directly instead of using
 * this helper.
 */
export function successFromExitCode(
  exitCode: number | string | undefined | null,
  semanticSuccessCodes?: readonly number[],
): boolean {
  if (exitCode === undefined || exitCode === null) return true;
  const n = typeof exitCode === "string" ? Number.parseInt(exitCode, 10) : exitCode;
  if (!Number.isFinite(n)) return false;
  if (n < 0 || n > 255) return false;
  if (semanticSuccessCodes?.includes(n)) return true;
  return n <= 1;
}

export { POLICY_URL } from "./config.js";
export type { InitOptions, Status, TrackFields, UsageEvent } from "./types.js";
