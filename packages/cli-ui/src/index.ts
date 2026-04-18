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
