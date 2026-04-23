import { buildCheckOutput, buildNotFoundOutput } from "./output.js";
import { parseCheckInput, ecosystemToTargetType } from "./input.js";
import { translateDownloadError } from "./translate-error.js";
import type {
  CheckInput,
  CheckOutput,
  NotFoundOutput,
  PackageEcosystem,
  PackageTarget,
} from "./types.js";

/**
 * Result type from the orchestrator — a tagged union so callers can pick
 * the JSON shape branch without reading the `found` key.
 */
export type CheckPackageResult =
  | { kind: "found"; output: CheckOutput }
  | { kind: "not-found"; output: NotFoundOutput };

/**
 * Registry-first, scan-on-miss orchestrator for `check <target>`.
 *
 * This is the shared flow ai-trust uses by default, and that opena2a-cli
 * uses when not spawn-delegating to hackmyagent. hackmyagent itself
 * keeps its scan-first flow and calls `buildCheckOutput` directly on
 * the merged (scan + registry) data; it doesn't need this orchestrator.
 *
 * Flow:
 *   1. Query the registry.
 *   2. Registry found → build CheckOutput from trust data (source=registry).
 *   3. Registry miss + mode=registry-only → NotFoundOutput.
 *   4. Registry miss + mode=scan-on-miss + scan adapter set → run scan.
 *      - Scan OK → build CheckOutput from scan data (source=local-scan).
 *      - Scan error → translateDownloadError, NotFoundOutput.
 *   5. Registry miss + mode=scan-on-miss + skillFallback set → try skill.
 *      - Skill match → CheckOutput with source=skill.
 *      - Skill miss  → NotFoundOutput.
 *   6. Otherwise → NotFoundOutput with default hint.
 */
export async function checkPackage(input: CheckInput): Promise<CheckPackageResult> {
  const parsed = parseCheckInput(input.target);
  const ecosystem: PackageEcosystem = parsed.ecosystem;
  const type: PackageTarget =
    ecosystemToTargetType(ecosystem) ?? "npm-package";

  // 1. Registry lookup
  let registryError: Error | null = null;
  try {
    const trust = await input.registry(parsed.normalizedName, input.type);
    if (trust.found) {
      return {
        kind: "found",
        output: buildCheckOutput({
          name: trust.name ?? parsed.normalizedName,
          type,
          registry: trust,
        }),
      };
    }
  } catch (err) {
    registryError = err instanceof Error ? err : new Error(String(err));
  }

  // 2. registry-only mode → bail with a not-found
  if (input.mode === "registry-only") {
    return {
      kind: "not-found",
      output: buildNotFoundOutput({
        name: parsed.normalizedName,
        ecosystem,
        error: registryError?.message,
      }),
    };
  }

  // 3. scan-on-miss: try the scan adapter first
  if (input.scan) {
    try {
      const scan = await input.scan(parsed.normalizedName);
      return {
        kind: "found",
        output: buildCheckOutput({
          name: parsed.normalizedName,
          type,
          scan,
        }),
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const translated = translateDownloadError(parsed.normalizedName, message);
      if (translated !== undefined) {
        return {
          kind: "not-found",
          output: buildNotFoundOutput({
            name: parsed.normalizedName,
            ecosystem,
            errorHint: translated.errorHint,
            suggestions: translated.suggestions,
            error: message,
          }),
        };
      }
      return {
        kind: "not-found",
        output: buildNotFoundOutput({
          name: parsed.normalizedName,
          ecosystem,
          error: message,
        }),
      };
    }
  }

  // 4. skill fallback (HMA-only in 0.1.0)
  if (input.skillFallback) {
    try {
      const skill = await input.skillFallback(parsed.normalizedName);
      if (skill) {
        return {
          kind: "found",
          output: {
            name: skill.name,
            type: "skill",
            source: "skill",
          },
        };
      }
    } catch {
      // fall through to generic not-found
    }
  }

  return {
    kind: "not-found",
    output: buildNotFoundOutput({
      name: parsed.normalizedName,
      ecosystem,
    }),
  };
}
