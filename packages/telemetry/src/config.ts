import { homedir, hostname, platform as osPlatform } from "node:os";
import { join } from "node:path";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { randomUUID, createHash } from "node:crypto";
import { execSync } from "node:child_process";
import type { SuppressionReason } from "./types.js";

export const POLICY_URL = "https://opena2a.org/telemetry";
export const DEFAULT_ENDPOINT = "https://api.oa2a.org/api/v1/telemetry/v1/event";
const ENV_OPT_OUT = "OPENA2A_TELEMETRY";
const ENV_ENDPOINT = "OPENA2A_TELEMETRY_URL";
const ENV_DEBUG = "OPENA2A_TELEMETRY_DEBUG";
const ENV_DO_NOT_TRACK = "DO_NOT_TRACK";

/**
 * Vendor markers that indicate a CI/build environment by their mere
 * presence. `CI` and `CONTINUOUS_INTEGRATION` are handled separately
 * because they carry a meaningful value (some runners export `CI=false`).
 */
const CI_VENDOR_ENV_VARS = [
  "GITHUB_ACTIONS",
  "GITLAB_CI",
  "CIRCLECI",
  "TRAVIS",
  "JENKINS_URL",
  "BUILDKITE",
  "DRONE",
  "TEAMCITY_VERSION",
  "TF_BUILD",
  "CODEBUILD_BUILD_ID",
  "APPVEYOR",
  "BITBUCKET_BUILD_NUMBER",
  "HEROKU_TEST_RUN_ID",
  "SEMAPHORE",
  "WOODPECKER_CI",
  "NETLIFY",
  "VERCEL",
  "CF_PAGES",
] as const;

export interface TelemetryConfig {
  enabled: boolean;
  installId: string;
}

export interface ConfigPaths {
  dir: string;
  file: string;
}

export function configPaths(): ConfigPaths {
  const xdg = process.env.XDG_CONFIG_HOME;
  const dir = xdg
    ? join(xdg, "opena2a")
    : join(homedir(), ".config", "opena2a");
  return { dir, file: join(dir, "telemetry.json") };
}

function readConfigFile(file: string): Partial<TelemetryConfig> | null {
  if (!existsSync(file)) return null;
  try {
    const raw = readFileSync(file, "utf8");
    const parsed = JSON.parse(raw) as Partial<TelemetryConfig>;
    return parsed;
  } catch {
    return null;
  }
}

function writeConfigFile(paths: ConfigPaths, cfg: TelemetryConfig): void {
  if (!existsSync(paths.dir)) {
    mkdirSync(paths.dir, { recursive: true, mode: 0o700 });
  }
  writeFileSync(paths.file, JSON.stringify(cfg, null, 2) + "\n", {
    mode: 0o600,
  });
}

function hashToUuid(seed: string): string {
  const hash = createHash("sha256").update(seed).digest("hex");
  return [
    hash.slice(0, 8),
    hash.slice(8, 12),
    "4" + hash.slice(13, 16),
    "8" + hash.slice(17, 20),
    hash.slice(20, 32),
  ].join("-");
}

/**
 * Read the OS-level machine identifier.
 *
 * Linux: /etc/machine-id (systemd) or /var/lib/dbus/machine-id (older).
 * macOS: IOPlatformUUID via `ioreg -rd1 -c IOPlatformExpertDevice`.
 * Windows: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid.
 *
 * Returns the raw identifier on success; null when unavailable, the
 * platform isn't supported, or the probe command fails. Never throws.
 */
function readMachineIdRaw(): string | null {
  try {
    const plat = osPlatform();
    if (plat === "linux") {
      for (const p of ["/etc/machine-id", "/var/lib/dbus/machine-id"]) {
        if (existsSync(p)) {
          const v = readFileSync(p, "utf8").trim();
          if (v) return v;
        }
      }
      return null;
    }
    if (plat === "darwin") {
      const out = execSync("ioreg -rd1 -c IOPlatformExpertDevice", {
        timeout: 1500,
        stdio: ["ignore", "pipe", "ignore"],
        encoding: "utf8",
      });
      const m = out.match(/"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]+)"/);
      return m ? m[1] : null;
    }
    if (plat === "win32") {
      const out = execSync(
        'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
        { timeout: 1500, stdio: ["ignore", "pipe", "ignore"], encoding: "utf8" },
      );
      const m = out.match(/MachineGuid\s+REG_SZ\s+([0-9A-Fa-f-]+)/);
      return m ? m[1] : null;
    }
  } catch {
    // probe failed (timeout, missing binary, sandboxed env) — fall through
  }
  return null;
}

/**
 * Stable-per-machine install ID.
 *
 * Persisted in the config file on first call. If absent, derived from a
 * platform-specific source in this priority order:
 *
 *   1. OS machine-id (Linux /etc/machine-id, macOS IOPlatformUUID,
 *      Windows MachineGuid) — purpose-built stable per-machine
 *      identifier. High entropy, not predictable from hostnames.
 *   2. Hash of hostname + platform + node major version — fallback for
 *      sandboxed/container environments where the probe in (1) fails.
 *   3. randomUUID() — last resort; rotates on every config-file rebuild.
 *
 * History: an earlier implementation (v0.1.x) keyed on npm-cache mtime
 * bucketed to 30 days, which rotated install_ids every month even on
 * stable machines AND fell back to randomUUID() in containers where the
 * cache wasn't persisted — both inflated "unique installs" numbers in
 * production.
 *
 * Privacy: the raw machine-id / hostname is never transmitted. SHA-256
 * is applied locally and only the hash is sent to the Registry. The
 * hash is irreversible. install_id is also user-rotatable via
 * `<tool> telemetry reset` (deletes the config file; next run picks a
 * fresh ID — or the same ID if the machine-id source is stable).
 *
 * Rainbow-table resistance: machine-id values on Linux/macOS/Windows
 * are random per-install (Linux machine-id is a random 128-bit value
 * generated at install time; macOS IOPlatformUUID is per-device).
 * Hostname fallback is less resistant — predictable patterns like
 * `runner-12345` in CI environments are theoretically guessable — but
 * still a one-way hash. Users in privacy-sensitive environments should
 * prefer (1) by ensuring `/etc/machine-id` exists, or run
 * `<tool> telemetry reset` to opt into a random ID.
 */
function deriveInstallId(): string {
  const machineId = readMachineIdRaw();
  if (machineId) {
    return hashToUuid(`mid:${machineId}`);
  }
  try {
    const host = hostname();
    if (host && host !== "localhost" && host !== "") {
      const seed = `host:${host}:${osPlatform()}:${process.versions.node.split(".")[0]}`;
      return hashToUuid(seed);
    }
  } catch {
    // hostname() failed — fall through
  }
  return randomUUID();
}

function envOptOut(env: NodeJS.ProcessEnv): boolean {
  const v = env[ENV_OPT_OUT];
  if (v === undefined) return false;
  const lower = v.toLowerCase();
  return lower === "off" || lower === "0" || lower === "false" || lower === "no";
}

/**
 * True when the variable is set to something other than an explicit
 * "no" value. Unset, empty, "0", "false" and "no" all read as false.
 */
function envTruthy(v: string | undefined): boolean {
  if (v === undefined) return false;
  const lower = v.trim().toLowerCase();
  if (lower === "") return false;
  return lower !== "0" && lower !== "false" && lower !== "no";
}

/**
 * Explicit opt-IN. Only overrides the automatic suppressions below
 * (CI / DO_NOT_TRACK) — never a deliberate opt-out held in the config
 * file. Lets us exercise the real ingest path from our own CI without
 * reopening the door to every other runner on the internet.
 */
function envOptIn(env: NodeJS.ProcessEnv): boolean {
  const v = env[ENV_OPT_OUT];
  if (v === undefined) return false;
  const lower = v.toLowerCase();
  return lower === "on" || lower === "1" || lower === "true" || lower === "yes";
}

/**
 * Detect a CI / build environment.
 *
 * Why this exists: install_id is derived from the OS machine-id, and
 * falls back to a hash of the hostname when that probe fails (see
 * `deriveInstallId`). CI runners are ephemeral containers — no
 * machine-id, and a fresh random hostname per job. Every CI run
 * therefore minted a brand-new install_id and was counted as a distinct
 * install/active user. With no suppression, adoption metrics measure
 * our own pipelines more than our users, and the error grows with build
 * frequency rather than with real usage.
 *
 * Bots are not users. Suppressing here (rather than filtering
 * server-side) means the event is never sent at all — cheaper, and it
 * keeps the Registry from having to guess which IDs were real.
 */
export function isCI(env: NodeJS.ProcessEnv = process.env): boolean {
  if (envTruthy(env.CI)) return true;
  if (envTruthy(env.CONTINUOUS_INTEGRATION)) return true;
  return CI_VENDOR_ENV_VARS.some((key) => envTruthy(env[key]));
}

/**
 * Honor the cross-vendor `DO_NOT_TRACK` convention
 * (https://consoledonottrack.com/). Any value except an explicit
 * "no" value opts the user out.
 */
export function doNotTrack(env: NodeJS.ProcessEnv = process.env): boolean {
  return envTruthy(env[ENV_DO_NOT_TRACK]);
}

/**
 * Which automatic suppression (if any) is currently in force.
 *
 * Returns null when an explicit OPENA2A_TELEMETRY=on overrides them, or
 * when neither applies. Exposed so `status()` can explain *why* telemetry
 * is off — a bare "off" reads as "you turned this off", and sends users
 * chasing a config flip that automatic suppression will just re-apply.
 */
export function autoSuppressionReason(
  env: NodeJS.ProcessEnv = process.env,
): SuppressionReason | null {
  if (envOptIn(env)) return null;
  if (isCI(env)) return "ci";
  if (doNotTrack(env)) return "do-not-track";
  return null;
}

/**
 * Load (and lazily create) the telemetry config.
 *
 * Precedence for `enabled`:
 *   1. OPENA2A_TELEMETRY set to an off value — always wins.
 *   2. config file `enabled: false` — a deliberate opt-out; nothing
 *      re-enables it, including OPENA2A_TELEMETRY=on.
 *   3. CI environment or DO_NOT_TRACK — suppressed, unless
 *      OPENA2A_TELEMETRY is set to an explicit on value.
 *   4. default ON (matches spec).
 *
 * The install_id is always persisted on first call so subsequent runs
 * (and subsequent tools on the same machine) report the same ID.
 *
 * Note that CI/DO_NOT_TRACK suppression is computed per-invocation and
 * deliberately NOT written to the config file: the file records what the
 * user chose, not where the process happened to run.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): {
  config: TelemetryConfig;
  paths: ConfigPaths;
  suppressedBy: SuppressionReason | null;
} {
  const paths = configPaths();
  const file = readConfigFile(paths.file);
  const installId = file?.installId ?? deriveInstallId();
  const fileEnabled = file?.enabled ?? true;
  const envDisabled = envOptOut(env);
  const suppressedBy = autoSuppressionReason(env);
  const enabled = !envDisabled && fileEnabled && suppressedBy === null;

  if (!file || !file.installId || file.enabled === undefined) {
    try {
      writeConfigFile(paths, { enabled: fileEnabled, installId });
    } catch {
      // best-effort persistence; running in a sandbox without HOME is fine.
    }
  }

  // Only attribute the off-state to the environment when the user has NOT
  // opted out themselves. Someone who ran `telemetry off` should not be
  // told CI is the reason.
  const userOptedOut = envDisabled || !fileEnabled;

  return {
    config: { enabled, installId },
    paths,
    suppressedBy: userOptedOut ? null : suppressedBy,
  };
}

export function setEnabled(enabled: boolean): TelemetryConfig {
  const paths = configPaths();
  const existing = readConfigFile(paths.file);
  const installId = existing?.installId ?? deriveInstallId();
  const cfg: TelemetryConfig = { enabled, installId };
  writeConfigFile(paths, cfg);
  return cfg;
}

export function endpointURL(env: NodeJS.ProcessEnv = process.env): string {
  return env[ENV_ENDPOINT] ?? DEFAULT_ENDPOINT;
}

export function debugPrintEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[ENV_DEBUG]?.toLowerCase() === "print";
}
