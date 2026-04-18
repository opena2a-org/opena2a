/**
 * Trust-relevance tier for a package.
 *
 * - `native`: AI-specific package (MCP server, A2A agent, skill, AI tool, LLM).
 *             Full trust verification applies. Registry data is authoritative.
 * - `adjacent`: General-purpose package that lives inside an AI agent's trust
 *               boundary (LLM client, credential handler, prompt parser, etc.).
 *               Stubbed in v0.3; reserved for v0.4 Tier 2 work.
 * - `unrelated`: General-purpose library with no AI-specific surface. Out of
 *                scope for ai-trust; deferred to HackMyAgent for security scanning.
 * - `unknown`: Cannot confidently classify. Treated as unrelated for audit
 *              output but flagged so callers can surface uncertainty.
 */
export type Tier = "native" | "adjacent" | "unrelated" | "unknown";

/**
 * Why a package is in its tier. Used by CLIs to render "reason" chips and
 * drive AI-specific interpretation (e.g. "credential_handler" means a finding
 * in this package affects your LLM API key).
 *
 * The set is deliberately small and curated. It is NOT a free-form tag.
 */
export type ReasonTag =
  | "llm_client"            // openai, @anthropic-ai/sdk, etc.
  | "mcp_transport"         // @modelcontextprotocol/sdk, jsonrpc libs
  | "credential_handler"    // dotenv, keytar, AWS secrets manager
  | "crypto_primitive"      // @noble/*, tweetnacl — used for agent identity
  | "prompt_loader"         // js-yaml, gray-matter — used to load skills/prompts
  | "ai_framework"          // langchain, llamaindex
  | "agent_runtime";        // temporal, bullmq, vercel/ai — runs the agent loop

export interface ClassificationResult {
  /** The tier the package falls into. */
  tier: Tier;
  /**
   * Reason tags explaining why a non-native package is AI-adjacent. Empty for
   * native / unrelated / unknown tiers.
   */
  reasons: ReasonTag[];
  /**
   * Short human-readable explanation. Useful for CLI output; not machine-parseable.
   */
  reasoning: string;
}

/**
 * Input to the classifier. `packageType` is the registry's stored package_type
 * value if known. When passed, it is the strongest signal and overrides name-
 * based heuristics.
 */
export interface ClassifyInput {
  /** Package name (e.g. "@modelcontextprotocol/server-filesystem"). */
  name: string;
  /** Registry package_type, if known. e.g. "mcp_server" | "a2a_agent" | "library". */
  packageType?: string;
}
