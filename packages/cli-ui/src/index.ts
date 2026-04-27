/**
 * @opena2a/cli-ui — Shared terminal UI primitives for OpenA2A CLIs.
 *
 * One source of truth for score meters, trust level legends, verdict colors,
 * dividers, and other output components. Used by ai-trust, hackmyagent, and
 * opena2a-cli so UX stays consistent across the platform.
 */

export { scoreMeter, miniMeter } from "./meters.js";
export { divider } from "./divider.js";
export {
  normalizeVerdict,
  verdictColor,
  type Verdict,
} from "./verdict.js";
export {
  trustLevelLabel,
  trustLevelColor,
  trustLevelLegend,
  scoreColor,
  type TrustLevel,
} from "./trust-level.js";
export { formatScanAge } from "./scan-age.js";
export {
  buildCategorySummaries,
  buildVerdict,
  classifyCategory,
  renderObservationsBlock,
  ALL_CATEGORY_LABELS,
  type ArtifactLine,
  type CategorizableFinding,
  type CategorySummary,
  type ChecksSummary,
  type ObservationsInput,
  type RenderedLine,
  type RenderedObservations,
  type SurfaceSummary,
  type VerdictFinding,
  type VerdictStatus,
} from "./observations.js";
export {
  isRenderableAnalystFinding,
  formatAnalystDescription,
  capAnalystThreatLevel,
  formatAnalystConfidence,
  LOW_CONFIDENCE_CAP,
  type AnalystFindingLike,
  type FormattedDescription,
} from "./analyst-render.js";
export {
  renderCheckBlock,
  type CheckBlockInput,
  type CheckBlockLine,
  type RenderedCheck,
  type CheckTone,
} from "./check-block.js";
export {
  renderNotFoundBlock,
  type NotFoundBlockInput,
  type NotFoundBlockLine,
  type RenderedNotFound,
  type NotFoundTone,
} from "./not-found-block.js";
export {
  renderNextSteps,
  type NextStepsCta,
  type NextStepsInput,
  type NextStepsLine,
  type RenderedNextSteps,
  type NextStepsTone,
} from "./next-steps.js";
export {
  versionLine,
  type TelemetryStatusLike,
  type VersionLineInput,
} from "./version-line.js";
export {
  runTelemetryCommand,
  type TelemetryAction,
  type TelemetryCommandInput,
} from "./telemetry-command.js";
export {
  renderCheckRichBlock,
  type CheckRichBlockInput,
  type RenderedRichBlock,
  type RichAlternativeSuggestion,
  type RichArtifactType,
  type RichBlockHeaderSignals,
  type RichBlockMetaLine,
  type RichBlockSection,
  type RichBlockSectionLine,
  type RichBlockTone,
  type RichObservationFinding,
} from "./check-rich-block.js";
export {
  renderHardcodedSecretsBlock,
  type RenderedSecretsBlock,
  type SecretLike,
  type SecretsBlockInput,
  type SecretsBlockLine,
  type SecretsTone,
} from "./hardcoded-secrets-block.js";
export {
  renderSkillMisuseNarrative,
  renderSkillNarrativeBlock,
  type PermissionStatusLike,
  type RenderedMisuseNarrative,
  type RenderedSkillNarrative,
  type SkillNarrativeLike,
  type SkillNarrativeLine,
  type SkillNarrativeTone,
  type ToolCallCountLike,
} from "./skill-narrative-block.js";
export {
  renderMcpNarrativeBlock,
  type McpNarrativeLike,
  type McpNarrativeLine,
  type McpNarrativeTone,
  type McpToolLike,
  type RenderedMcpNarrative,
} from "./mcp-narrative-block.js";
export {
  renderVerdictReasoningBlock,
  type RenderedVerdictReasoning,
  type VerdictReasoningInput,
  type VerdictReasoningLine,
  type VerdictReasoningStatementLike,
  type VerdictTier,
  type VerdictTone,
} from "./verdict-reasoning-block.js";
export {
  renderActionGradientBlock,
  type ActionGradientInput,
  type ActionGradientLine,
  type ActionGradientTier,
  type ActionGradientTone,
  type NextStepLike,
  type RenderedActionGradient,
} from "./action-gradient-block.js";
export {
  MCP_THREAT_MODEL_QUESTIONS,
  SKILL_THREAT_MODEL_QUESTIONS,
  threatModelQuestionsFor,
  type ThreatModelArtifactType,
} from "./threat-model-questions.js";
export {
  sanitizeArray,
  sanitizeForTerminal,
} from "./terminal-safe.js";
