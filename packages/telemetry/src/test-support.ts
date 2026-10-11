/**
 * Test-only helpers. Excluded from the published build via the tsconfig
 * `exclude` list, so this never reaches `dist` or npm.
 *
 * Why this file exists: the suites assert default-ON telemetry behaviour,
 * but telemetry is deliberately suppressed in CI (see `isCI` in config.ts).
 * Running the suites on a GitHub Actions runner — where CI=true and
 * GITHUB_ACTIONS=true are always set — would otherwise flip every
 * default-ON assertion and turn the build red for the wrong reason.
 * Scrub the suppression signals so the tests exercise the behaviour they
 * claim to, on a laptop and on a runner alike.
 */

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { CI_VENDOR_ENV_VARS, TEST_RUNNER_ENV_VARS } from "./config.js";

/**
 * Every env var that suppresses telemetry.
 *
 * Derived from the real vendor list rather than hand-copied, so adding a
 * vendor to config.ts cannot silently desync this. A duplicated list would
 * fail only on a contributor's machine that happens to set the new var —
 * never on our own runners, which set CI/GITHUB_ACTIONS and are already
 * scrubbed — surfacing later as an unrelated-looking test failure.
 *
 * The test-runner markers are here because these suites run under Vitest,
 * which sets `VITEST` in this very process.
 */
export const SUPPRESSION_ENV_VARS = [
  ...CI_VENDOR_ENV_VARS,
  ...TEST_RUNNER_ENV_VARS,
  "CI",
  "CONTINUOUS_INTEGRATION",
  "DO_NOT_TRACK",
] as const;

/** The variables `os.tmpdir()` reads, on POSIX and on Windows. */
const TEMP_ROOT_ENV_VARS = ["TMPDIR", "TMP", "TEMP"] as const;

export type SavedEnv = Record<string, string | undefined>;

/**
 * Clear every suppression var, returning the prior values for restore.
 * The temporary-directory variables are saved too (not cleared), so that
 * `markPersistent` and `markTemporary` are undone by the same restore.
 */
export function scrubSuppressionEnv(): SavedEnv {
  const saved: SavedEnv = {};
  for (const key of SUPPRESSION_ENV_VARS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  for (const key of TEMP_ROOT_ENV_VARS) saved[key] = process.env[key];
  return saved;
}

function setTempRoot(dir: string): void {
  for (const key of TEMP_ROOT_ENV_VARS) process.env[key] = dir;
}

/**
 * Make `dir`, a fresh mkdtemp directory the suites use as their config
 * home, read as a persistent home. Temporary-home suppression would
 * otherwise turn every default-ON assertion off. `os.tmpdir()` is pointed
 * at a directory inside `dir`, which `dir` itself is not under.
 */
export function markPersistent(dir: string): void {
  const elsewhere = join(dir, "tmp");
  mkdirSync(elsewhere, { recursive: true });
  setTempRoot(elsewhere);
}

/** Make `dir` read as a temporary home: `os.tmpdir()` becomes `dir`. */
export function markTemporary(dir: string): void {
  setTempRoot(dir);
}

/** Restore what `scrubSuppressionEnv` cleared. */
export function restoreSuppressionEnv(saved: SavedEnv): void {
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}
