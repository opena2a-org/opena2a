/**
 * @opena2a/ai-classifier
 *
 * Decide whether a package is AI-native, AI-adjacent, or unrelated so
 * ai-trust, HMA, and opena2a-cli can route it correctly.
 *
 * v0.1: Tier 1 (native) + Tier 3 (unrelated) only. Tier 2 (adjacent) is
 * stubbed for v0.4 when the curated adjacent allowlist lands.
 */

export type {
  Tier,
  ReasonTag,
  ClassificationResult,
  ClassifyInput,
} from "./types.js";

export {
  classify,
  isAiTrustScope,
  isHmaRoute,
  tierLabel,
} from "./classify.js";

export {
  AI_NATIVE_PACKAGE_TYPES,
  LIBRARY_PACKAGE_TYPE,
  isNativeType,
  isLibraryType,
} from "./native-types.js";

export {
  UNRELATED_PACKAGE_NAMES,
  UNRELATED_SCOPE_PREFIXES,
  isKnownUnrelatedName,
} from "./unrelated-names.js";
