/**
 * Threat-model questions — static templates per artifact type.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§6).
 * Curated by [CHIEF-CSR]. Rendered verbatim. Lives in cli-ui (not in
 * the registry) because the questions don't change per package — they
 * give the CISO a stable mental model. v1 is intentionally a static
 * baseline; refinement is post-v1 with 30-day CISO feedback.
 */

export const SKILL_THREAT_MODEL_QUESTIONS: readonly string[] = Object.freeze([
  "Where will users invoke this skill? Is the CWD bounded to a project the user owns, or could it run in a directory containing secrets (e.g. ~/.ssh, ~/.aws)?",
  "Do you require pinning to a specific skill version, or does your fleet auto-update on publish?",
  "Is your Claude API key scoped per-user, or shared across a tenant where one user's prompt can affect another's?",
]);

export const MCP_THREAT_MODEL_QUESTIONS: readonly string[] = Object.freeze([
  "Will the agent that connects to this MCP be capable of writing outside its task scope if it is prompt-injected?",
  "Does your config-level scope restriction (allowedDirectories, allowedHosts, etc.) use realpath or string-prefix matching?",
  "Is there a snapshot or backup before the agent has write access?",
]);

export type ThreatModelArtifactType = "skill" | "mcp";

/**
 * Resolve the static template for a given artifact type. Returns a
 * frozen list — callers must not mutate. Returns an empty list for
 * artifact types without v1 templates (npm/pypi/a2a fall back to the
 * legacy renderer + footer per brief §3.8, so they shouldn't reach
 * this function in practice).
 */
export function threatModelQuestionsFor(
  artifactType: ThreatModelArtifactType,
): readonly string[] {
  if (artifactType === "skill") return SKILL_THREAT_MODEL_QUESTIONS;
  if (artifactType === "mcp") return MCP_THREAT_MODEL_QUESTIONS;
  return [];
}
