import type { ClassificationResult, ClassifyInput, Tier } from "./types.js";
import { isLibraryType, isNativeType } from "./native-types.js";
import { isKnownUnrelatedName } from "./unrelated-names.js";

/**
 * Classify a package by tier.
 *
 * Decision order:
 *   1. Registry-supplied `packageType` is the strongest signal (it comes from
 *      the Registry's own classification pipeline).
 *   2. If no type is given, fall back to the name-based unrelated allowlist
 *      to catch common libraries (chalk, typescript, @types/*).
 *   3. Otherwise, return `unknown` so callers can surface uncertainty rather
 *      than risk mislabeling an AI package as unrelated.
 *
 * Tier 2 (adjacent) is stubbed for v0.3. It returns `unknown` today. Once the
 * curated adjacent allowlist lands in v0.4, this function will route matches
 * into Tier 2 with the appropriate reason tags.
 */
export function classify(input: ClassifyInput): ClassificationResult {
  const { name, packageType } = input;

  // 1. Strongest signal: registry package_type.
  if (isNativeType(packageType)) {
    return {
      tier: "native",
      reasons: [],
      reasoning: `Registered as ${packageType} in the OpenA2A Registry`,
    };
  }

  if (isLibraryType(packageType)) {
    return {
      tier: "unrelated",
      reasons: [],
      reasoning: "Registered as a general-purpose library",
    };
  }

  // 2. No registry type: fall back to name-based allowlist for well-known
  //    general-purpose libraries.
  if (isKnownUnrelatedName(name)) {
    return {
      tier: "unrelated",
      reasons: [],
      reasoning: `Recognized as a general-purpose library (${name})`,
    };
  }

  // 3. Can't classify confidently. Return unknown so callers can ask the
  //    user, skip, or defer to a fresh registry lookup.
  return {
    tier: "unknown",
    reasons: [],
    reasoning: "No registry classification or allowlist match",
  };
}

/**
 * Quick boolean: is this package worth scanning with ai-trust, or should we
 * defer to HMA? True for tier === "native". Returns false for unrelated,
 * unknown, and (in a future release) adjacent.
 */
export function isAiTrustScope(result: ClassificationResult): boolean {
  return result.tier === "native";
}

/**
 * Quick boolean: is this package a non-AI library that should be routed to HMA?
 */
export function isHmaRoute(result: ClassificationResult): boolean {
  return result.tier === "unrelated";
}

/**
 * Map a tier to a short label for CLI output ("AI package", "library", etc.).
 */
export function tierLabel(tier: Tier): string {
  switch (tier) {
    case "native":
      return "AI package";
    case "adjacent":
      return "AI-adjacent";
    case "unrelated":
      return "library";
    case "unknown":
      return "unknown";
  }
}
