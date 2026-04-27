import { homedir, platform as osPlatform } from "node:os";
import { join } from "node:path";
import { mkdirSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
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
 * Persisted in the config file. If absent, derived from a hash of
 * platform + node-major + npm-cache-dir mtime so npx invocations on
 * the same machine produce the same ID for ~30 days, then rotate.
 * Falls back to a fresh UUID if the cache stat is unavailable.
 */
function deriveInstallId(): string {
  try {
    const cacheDir = process.env.npm_config_cache
      ?? join(homedir(), ".npm");
    if (existsSync(cacheDir)) {
      const mtimeBucket = Math.floor(
        statSync(cacheDir).mtimeMs / (1000 * 60 * 60 * 24 * 30),
      );
      const seed = `${osPlatform()}:${process.versions.node.split(".")[0]}:${cacheDir}:${mtimeBucket}`;
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
