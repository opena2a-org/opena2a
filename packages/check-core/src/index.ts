/**
 * @opena2a/check-core — Data-shape and orchestration primitives for the
 * `check` command across OpenA2A CLIs.
 *
 * One implementation of:
 *   - input classification (npm / pypi / github / local / url)
 *   - download-error translation
 *   - registry-status → meter-gate mapping
 *   - canonical CheckOutput + NotFoundOutput JSON shape
 *   - registry-first, scan-on-miss orchestrator (with pluggable adapters)
 *
 * Rendering stays in `@opena2a/cli-ui` (renderCheckBlock /
 * renderNotFoundBlock / renderNextSteps) — this package is data only.
 */

export {
  parseCheckInput,
  ecosystemToTargetType,
} from "./input.js";

export { translateDownloadError } from "./translate-error.js";

export { mapScanStatusForMeter } from "./scan-status.js";

export {
  buildCheckOutput,
  buildNotFoundOutput,
  type BuildCheckOutputInput,
  type BuildNotFoundInput,
} from "./output.js";

export {
  checkPackage,
  type CheckPackageResult,
} from "./check-package.js";

export type {
  CheckInput,
  CheckOutput,
  NotFoundOutput,
  PackageEcosystem,
  PackageTarget,
  ParsedCheckInput,
  RegistryAdapter,
  ScanAdapter,
  ScanResult,
  SkillAdapter,
  SkillResult,
  TranslatedError,
  TrustData,
} from "./types.js";
