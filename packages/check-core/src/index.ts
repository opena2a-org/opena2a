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
 *   - PackageNarrative wire types for skill + mcp rich-context (v1)
 *   - secret-rotation lookup (drives the rotate-this-key UX)
 *   - deterministic rule engine for verdict reasoning + action gradient
 *
 * Rendering stays in `@opena2a/cli-ui` (renderCheckBlock /
 * renderNotFoundBlock / renderNextSteps / renderCheckRichBlock) —
 * this package is data only.
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

export type {
  ArtifactType,
  HardcodedSecret,
  HardcodedSecretsBlock,
  McpNarrative,
  McpTool,
  NextStep,
  PackageNarrative,
  PermissionDeltaStatus,
  PermissionStatus,
  SecretSeverity,
  SkillNarrative,
  ToolCallCount,
  VerdictReasoningStatement,
} from "./narrative.js";

export {
  SECRET_ROTATION_TABLE,
  enrichSecretRotation,
  lookupSecretRotation,
  type SecretRotationGuide,
} from "./secret-rotation.js";

export {
  runRuleEngine,
  type AttestationSummary,
  type PublisherSignals,
  type RuleArtifactType,
  type RuleEngineInput,
  type RuleEngineOutput,
  type RuleFinding,
  type ScanStatus,
  type TrustVerdict,
} from "./rule-engine.js";
