/**
 * AI-native package types. A package with one of these registry package_type
 * values is in Tier 1 (native) regardless of its name.
 *
 * This list mirrors the registry's `scannableTypes` (mcp_server, a2a_agent,
 * skill, ai_tool) plus `llm`. LLMs aren't auto-scanned by HMA (model weights
 * don't benefit from code scanning), but they are AI-native and belong in the
 * trust-verification flow.
 */
export const AI_NATIVE_PACKAGE_TYPES: ReadonlySet<string> = new Set([
  "mcp_server",
  "a2a_agent",
  "skill",
  "ai_tool",
  "llm",
]);

/**
 * Registry package_type value for general-purpose libraries. Packages with
 * this type are explicitly out of scope for ai-trust and get routed to HMA.
 */
export const LIBRARY_PACKAGE_TYPE = "library";

/**
 * Returns true for any package_type value that represents an AI-native package.
 */
export function isNativeType(packageType?: string): boolean {
  if (!packageType) return false;
  return AI_NATIVE_PACKAGE_TYPES.has(packageType);
}

/**
 * Returns true when the registry explicitly marks this as a general-purpose
 * library.
 */
export function isLibraryType(packageType?: string): boolean {
  return packageType === LIBRARY_PACKAGE_TYPE;
}
