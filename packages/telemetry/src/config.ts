import { homedir, hostname, platform as osPlatform } from "node:os";
import { join } from "node:path";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { randomUUID, createHash } from "node:crypto";

export const POLICY_URL = "https://opena2a.org/telemetry";
export const DEFAULT_ENDPOINT = "https://api.oa2a.org/api/v1/registry/telemetry/v1/event";
const ENV_OPT_OUT = "OPENA2A_TELEMETRY";
const ENV_ENDPOINT = "OPENA2A_TELEMETRY_URL";
const ENV_DEBUG = "OPENA2A_TELEMETRY_DEBUG";

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

/**
 * Stable-per-machine install ID.
 *
 * Persisted in the config file. If absent, derived from a hash of the
 * hostname + platform + node major version. Same machine → same ID,
 * across container restarts, npm-cache rebuilds, and indefinite time.
 *
 * History: an earlier implementation (v0.1.x) keyed on npm-cache mtime
 * bucketed to 30 days, which rotated install_ids every month even on
 * stable machines AND fell back to randomUUID() in containers where the
 * cache wasn't persisted — both inflated "unique installs" numbers in
 * production. This implementation lands stable IDs on the FIRST run and
 * keeps them stable forever (until the user runs `<tool> telemetry reset`
 * or the config file is destroyed).
 *
 * Privacy: hostname is hashed with SHA-256 + formatted into a UUID
 * shape. The Registry never sees plaintext hostname; the hash is
 * irreversible. install_id is also rotatable on demand by the user.
 *
 * Falls back to randomUUID() only if BOTH hostname() and the standard
 * /etc/machine-id-style env vars fail — vanishingly rare.
 */
function deriveInstallId(): string {
  try {
    const host = hostname();
    if (host && host !== "localhost" && host !== "") {
      const seed = `${host}:${osPlatform()}:${process.versions.node.split(".")[0]}`;
      const hash = createHash("sha256").update(seed).digest("hex");
      return [
        hash.slice(0, 8),
        hash.slice(8, 12),
        "4" + hash.slice(13, 16),
        "8" + hash.slice(17, 20),
        hash.slice(20, 32),
      ].join("-");
    }
  } catch {
    // fall through
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
 * Load (and lazily create) the telemetry config.
 *
 * Precedence for `enabled`:
 *   1. OPENA2A_TELEMETRY env var (always wins, per-invocation)
 *   2. config file `enabled` field
 *   3. default ON (matches spec)
 *
 * The install_id is always persisted on first call so subsequent runs
 * (and subsequent tools on the same machine) report the same ID.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): {
  config: TelemetryConfig;
  paths: ConfigPaths;
} {
  const paths = configPaths();
  const file = readConfigFile(paths.file);
  const installId = file?.installId ?? deriveInstallId();
  const fileEnabled = file?.enabled ?? true;
  const envDisabled = envOptOut(env);
  const enabled = !envDisabled && fileEnabled;

  if (!file || !file.installId || file.enabled === undefined) {
    try {
      writeConfigFile(paths, { enabled: fileEnabled, installId });
    } catch {
      // best-effort persistence; running in a sandbox without HOME is fine.
    }
  }

  return { config: { enabled, installId }, paths };
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
