import { homedir, hostname, platform as osPlatform, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { mkdirSync, readFileSync, writeFileSync, existsSync, unlinkSync, realpathSync } from "node:fs";
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
export const CI_VENDOR_ENV_VARS = [
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

/**
 * Variables a test runner sets in every process it runs tests in, and
 * which a CLI spawned from a test inherits: Vitest sets `VITEST`, Jest
 * `JEST_WORKER_ID`, and `node --test` sets `NODE_TEST_CONTEXT`.
 * `NODE_ENV=test` is deliberately absent: applications set it for their own
 * reasons, so it says nothing reliable about who started this CLI.
 */
export const TEST_RUNNER_ENV_VARS = [
  "VITEST",
  "JEST_WORKER_ID",
  "NODE_TEST_CONTEXT",
] as const;

export interface TelemetryConfig {
  enabled: boolean;
  /** null whenever telemetry is off: no identifier is derived, read or kept. */
  installId: string | null;
}

/** On-disk shape. `installId` is present only while telemetry is on. */
interface ConfigFile {
  enabled: boolean;
  installId?: string;
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

function readConfigFile(file: string): Partial<ConfigFile> | null {
  if (!existsSync(file)) return null;
  try {
    const raw = readFileSync(file, "utf8");
    const parsed: unknown = JSON.parse(raw);
    // A hand-edited file can hold any JSON value; only an object is a config.
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    return parsed as Partial<ConfigFile>;
  } catch {
    return null;
  }
}

/** The persisted install_id, if the file holds a usable one. */
function storedInstallId(file: Partial<ConfigFile> | null): string | undefined {
  const id = file?.installId;
  return typeof id === "string" && id !== "" ? id : undefined;
}

function writeConfigFile(paths: ConfigPaths, cfg: ConfigFile): void {
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
 * hash cannot be run backwards, but anyone who knows or guesses its
 * inputs can compute it again, so the install ID identifies the machine
 * and is personal data. No `telemetry reset` command exists; deleting
 * the config file re-derives the same ID while the machine-id source is
 * stable.
 *
 * Rainbow-table resistance: machine-id values on Linux/macOS/Windows
 * are random per-install (Linux machine-id is a random 128-bit value
 * generated at install time; macOS IOPlatformUUID is per-device).
 * Hostname fallback is less resistant — predictable patterns like
 * `runner-12345` in CI environments are theoretically guessable — and
 * a hash of a guessed hostname can be checked against a stored ID. Users
 * in privacy-sensitive environments should turn telemetry off with
 * OPENA2A_TELEMETRY=off or `<tool> telemetry off`.
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
  // Trim: trailing whitespace and newlines are routine in .env files,
  // docker-compose YAML, Dockerfile ENV, and $(cmd) substitution. An
  // opt-out must never fail open because the value had a stray space.
  const lower = v.trim().toLowerCase();
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
 * Explicit opt-IN. Overrides the *environmental* suppressions only (CI, a
 * test runner, a temporary home), never a deliberate opt-out, whether that
 * lives in the config file or in DO_NOT_TRACK. Lets us exercise the real
 * ingest path from our own CI and end-to-end tests without reopening the
 * door to every other runner on the internet.
 */
function envOptIn(env: NodeJS.ProcessEnv): boolean {
  const v = env[ENV_OPT_OUT];
  if (v === undefined) return false;
  const lower = v.trim().toLowerCase();
  return lower === "on" || lower === "1" || lower === "true" || lower === "yes";
}

/**
 * Detect a CI / build environment.
 *
 * Why this exists: install_id is derived from the OS machine-id, and
 * falls back to a hash of the hostname when that probe fails (see
 * `deriveInstallId`). CI runners are provisioned fresh for each job, so
 * the machine-id (or the hostname fallback) differs on every run — a CI
 * run typically minted a brand-new install_id and was counted as a
 * distinct install/active user. With no suppression, adoption metrics
 * measure our own pipelines more than our users, and the error grows
 * with build frequency rather than with real usage.
 *
 * Two limits worth knowing, since this reads like a complete fix and is
 * not one. Self-hosted or reused runners have a stable machine-id, so
 * they collapse onto a single persistent identity instead of inflating —
 * a different distortion. And `CI` is a proxy for ephemerality, not a
 * synonym: a throwaway `docker run`, a devcontainer rebuild or a
 * sandboxed `npx` hits the same fallback path while setting none of
 * these variables. This covers the CI-labeled share, not the whole class.
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
 * Detect a process started from inside a test runner.
 *
 * Test suites that exercise a CLI spawn it many times per run, and the
 * child inherits the runner's environment. Outside CI (a developer running
 * the suite locally) none of the CI variables is set, so every one of those
 * spawns used to send events as if a user had run the command.
 */
export function isTestRunner(env: NodeJS.ProcessEnv = process.env): boolean {
  return TEST_RUNNER_ENV_VARS.some((key) => envTruthy(env[key]));
}

/**
 * The path with every symlink in its longest existing prefix resolved, so
 * that `/var/...` and `/private/var/...` on macOS (or a symlinked TMPDIR)
 * compare equal. The part that does not exist yet is appended unchanged.
 */
function canonicalPath(p: string): string {
  const abs = resolve(p);
  try {
    return realpathSync.native(abs);
  } catch {
    const parent = dirname(abs);
    if (parent === abs) return abs;
    return join(canonicalPath(parent), basename(abs));
  }
}

/** True when `child` is `parent` or sits anywhere below it. */
function isWithin(child: string, parent: string): boolean {
  const rel = relative(parent, child);
  if (rel === "") return true;
  return rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

function safeHomedir(): string | null {
  try {
    return homedir();
  } catch {
    return null;
  }
}

/**
 * Detect a home directory that will not outlive this run: the telemetry
 * config directory, or the home directory itself, sits inside the system
 * temporary directory (`os.tmpdir()`).
 *
 * Why this exists: test suites and scripted jobs start a CLI with
 * `HOME=$(mktemp -d)` (or an equivalent `XDG_CONFIG_HOME`) so it cannot
 * touch the real home. The config file, and the install ID stored in it,
 * is then thrown away after every run, so each run looked like a first run
 * on a new machine.
 *
 * One limit: only `os.tmpdir()` is checked, which follows `TMPDIR` (`TEMP`
 * / `TMP` on Windows). A throwaway home somewhere else, such as a container
 * filesystem discarded after the job, is not detected here.
 *
 * The parameters exist for tests; callers use the defaults.
 */
export function isEphemeralHome(
  configDir: string = configPaths().dir,
  home: string | null = safeHomedir(),
  tempRoot: string = tmpdir(),
): boolean {
  const root = canonicalPath(tempRoot);
  // A temporary directory set to a filesystem root would contain every path.
  if (dirname(root) === root) return false;
  return [configDir, home].some(
    (p) => typeof p === "string" && p !== "" && isWithin(canonicalPath(p), root),
  );
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
 * Which environmental suppression (if any) is currently in force.
 *
 * Exposed so `status()` can explain *why* telemetry is off — a bare "off"
 * reads as "you turned this off", and sends users chasing a config flip
 * that suppression will just re-apply.
 *
 * Order matters, and the reasons are NOT peers:
 *
 *   - `DO_NOT_TRACK` is a deliberate user *intent*. A user exports it once
 *     in their shell profile and expects every tool to honor it. It sits in
 *     the same tier as `telemetry off` and is checked FIRST, so that
 *     `OPENA2A_TELEMETRY=on` — which we tell people to put in CI configs,
 *     Dockerfiles and Makefiles — can never silently override a privacy
 *     signal the user never touched.
 *   - CI-ness, a test runner and a temporary home are environmental
 *     *facts*, not choices, so an explicit opt-in may override them. They
 *     are the only things the opt-in overrides. Among them CI is reported
 *     first: a test suite running in CI is explained by the CI.
 *
 * The temporary-home check reads the paths this process would use (see
 * `isEphemeralHome`), not `env`.
 */
export function autoSuppressionReason(
  env: NodeJS.ProcessEnv = process.env,
): SuppressionReason | null {
  if (doNotTrack(env)) return "do-not-track";
  if (envOptIn(env)) return null;
  if (isCI(env)) return "ci";
  if (isTestRunner(env)) return "test-runner";
  if (isEphemeralHome()) return "ephemeral-home";
  return null;
}

/**
 * Load (and lazily create) the telemetry config.
 *
 * Precedence for `enabled`:
 *   1. OPENA2A_TELEMETRY set to an off value — always wins.
 *   2. config file `enabled: false` — a deliberate opt-out; nothing
 *      re-enables it, including OPENA2A_TELEMETRY=on.
 *   3. DO_NOT_TRACK — also a deliberate opt-out; likewise nothing
 *      re-enables it. Same tier as (2), not an environmental default.
 *   4. CI environment — suppressed, unless OPENA2A_TELEMETRY is set to an
 *      explicit on value. CI-ness is a fact about the machine, not a
 *      choice by the user, so an explicit opt-in may override it.
 *   5. Test runner, then temporary home: suppressed on the same terms as
 *      CI, and overridden by the same explicit opt-in.
 *   6. default ON (matches spec).
 *
 * The install_id exists only while telemetry is on. When it is on, the ID
 * is derived once and persisted so later runs (and other tools on the same
 * machine) report the same one. When it is off for ANY of the reasons
 * above, nothing is derived — no machine-id read, no `ioreg` / `reg query`
 * probe, no hostname hash — `installId` is null, and an ID left in the file
 * by an earlier run is deleted: the file keeps an explicit
 * `enabled: false` and loses the `installId` key, and a file that held
 * nothing but the default `enabled: true` plus an ID is removed. This never
 * writes `enabled: true`.
 *
 * Note that automatic suppression is computed per-invocation and
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
  const fileEnabled = file?.enabled ?? true;
  const envDisabled = envOptOut(env);
  const autoReason = autoSuppressionReason(env);
  const enabled = !envDisabled && fileEnabled && autoReason === null;

  let installId: string | null = null;
  if (enabled) {
    const stored = storedInstallId(file);
    installId = stored ?? deriveInstallId();
    if (!stored || file?.enabled === undefined) {
      try {
        writeConfigFile(paths, { enabled: true, installId });
      } catch {
        // best-effort persistence; running in a sandbox without HOME is fine.
      }
    }
  } else if (file && "installId" in file) {
    forgetInstallId(paths, file.enabled === false);
  }

  // Attribute the off-state to the reason a consumer must actually explain,
  // in precedence order:
  //
  //   - OPENA2A_TELEMETRY=off wins outright, so report it. Without a code
  //     here a CLI can only say a bare "off" and suggest `telemetry on` —
  //     which cannot work, because rule 1 says env-off always wins.
  //   - A persisted `telemetry off` gets NO code: the ordinary toggle works,
  //     so a plain hint is the better affordance, and attributing it to the
  //     environment would tell the user something untrue about their own
  //     choice.
  //   - Otherwise the environment is the cause (DO_NOT_TRACK, CI, a test
  //     runner or a temporary home).
  const suppressedBy: SuppressionReason | null = envDisabled
    ? "env-opt-out"
    : !fileEnabled
      ? null
      : autoReason;

  return { config: { enabled, installId }, paths, suppressedBy };
}

/**
 * Delete a persisted install_id. An explicit `enabled: false` is kept;
 * anything else in the file is the default and is not written back, so
 * this never writes `enabled: true`. Best-effort, like every write here.
 */
function forgetInstallId(paths: ConfigPaths, keepOptOut: boolean): void {
  try {
    if (keepOptOut) writeConfigFile(paths, { enabled: false });
    else unlinkSync(paths.file);
  } catch {
    // read-only or missing config dir: nothing more we can do.
  }
}

/**
 * Persist the user's choice (`<tool> telemetry on|off`).
 *
 * `off` writes exactly `{"enabled":false}`: the install_id is deleted, not
 * kept for later. `on` never derives an ID itself — loadConfig() does that
 * on the next load, and only when telemetry is then actually on — and keeps
 * an existing ID only when no env opt-out or automatic suppression is
 * holding telemetry off.
 */
export function setEnabled(
  enabled: boolean,
  env: NodeJS.ProcessEnv = process.env,
): TelemetryConfig {
  const paths = configPaths();
  let cfg: ConfigFile = { enabled };
  if (enabled && !envOptOut(env) && autoSuppressionReason(env) === null) {
    const existingId = storedInstallId(readConfigFile(paths.file));
    if (existingId) cfg = { enabled: true, installId: existingId };
  }
  writeConfigFile(paths, cfg);
  return { enabled, installId: cfg.installId ?? null };
}

export function endpointURL(env: NodeJS.ProcessEnv = process.env): string {
  return env[ENV_ENDPOINT] ?? DEFAULT_ENDPOINT;
}

export function debugPrintEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[ENV_DEBUG]?.toLowerCase() === "print";
}
