/**
 * Verdict-reasoning block — renders the rule-engine output verbatim
 * under "Why VERIFIED / LISTED / BLOCKED / no score".
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§5).
 *
 * The rule engine in `@opena2a/check-core` produces a deterministic
 * `VerdictReasoningStatement[]`. This renderer applies the markers:
 *   - `positive` → `[ok]  <text>`
 *   - `gap`      → `1.    <text>` (numbered when 2+ gaps exist; bare
 *                   bullet otherwise)
 *   - `critical` → `CRITICAL  <text>` (uppercase severity prefix)
 *
 * Header label is derived from the verdict tier so callers don't have
 * to know the prose. For NOT_FOUND the function returns an empty block;
 * the orchestrator picks a different render path.
 */

/**
 * Local mirror of `VerdictReasoningStatement` from check-core. Defined
 * here so cli-ui stays dependency-light; structural typing means the
 * registry-sourced narrative passes through unchanged.
 */
export interface VerdictReasoningStatementLike {
  kind: "positive" | "gap" | "critical";
  text: string;
}

export type VerdictTier =
  | "VERIFIED"
  | "LISTED"
  | "LISTED_UNSCANNED"
  | "BLOCKED"
  | "NOT_FOUND";

export type VerdictTone = "default" | "good" | "warning" | "critical" | "dim";

export interface VerdictReasoningInput {
  tier: VerdictTier;
  statements: VerdictReasoningStatementLike[];
}

export interface VerdictReasoningLine {
  text: string;
  tone: VerdictTone;
}

export interface RenderedVerdictReasoning {
  /**
   * Section header label, e.g. "Why VERIFIED" / "Why LISTED, not
   * VERIFIED" / "Why BLOCKED" / "Why no score". Empty string for
   * NOT_FOUND (no block rendered).
   */
  header: string;
  lines: VerdictReasoningLine[];
}

function headerForTier(
  tier: VerdictTier,
  hasGaps: boolean,
  hasPositives: boolean,
): string {
  switch (tier) {
    case "VERIFIED":
      // Mockup 3.5 path: "Why VERIFIED despite findings" when there
      // are gaps alongside positives. Pure-clean is just "Why VERIFIED".
      if (hasGaps && hasPositives) return "Why VERIFIED despite findings";
      return "Why VERIFIED";
    case "LISTED":
      return "Why LISTED, not VERIFIED";
    case "LISTED_UNSCANNED":
      return "Why no score";
    case "BLOCKED":
      return "Why BLOCKED";
    case "NOT_FOUND":
      return "";
  }
}

function renderPositive(text: string): VerdictReasoningLine {
  return { text: `[ok]  ${text}`, tone: "good" };
}

function renderGap(
  text: string,
  numbered: boolean,
  index: number,
): VerdictReasoningLine {
  if (numbered) {
    // 2+ gaps → numbered list ("1.  ", "2.  ", ...).
    return { text: `${index + 1}.  ${text}`, tone: "warning" };
  }
  return { text: `-  ${text}`, tone: "warning" };
}

function renderCritical(text: string): VerdictReasoningLine {
  return { text: `CRITICAL  ${text}`, tone: "critical" };
}

export function renderVerdictReasoningBlock(
  input: VerdictReasoningInput,
): RenderedVerdictReasoning {
  const { tier, statements } = input;

  if (tier === "NOT_FOUND") {
    return { header: "", lines: [] };
  }

  const positives = statements.filter((s) => s.kind === "positive");
  const gaps = statements.filter((s) => s.kind === "gap");
  const criticals = statements.filter((s) => s.kind === "critical");

  const header = headerForTier(tier, gaps.length > 0, positives.length > 0);
  const lines: VerdictReasoningLine[] = [];

  if (tier === "BLOCKED") {
    // Critical-driven render.
    for (const c of criticals) lines.push(renderCritical(c.text));
    return { header, lines };
  }

  if (tier === "LISTED_UNSCANNED") {
    // Gap-only. The rule engine emits a single explanatory `gap`
    // statement; render it as a bare bullet to match the "Why no
    // score" prose intent.
    for (let i = 0; i < gaps.length; i++) {
      lines.push(renderGap(gaps[i].text, false, i));
    }
    return { header, lines };
  }

  // VERIFIED + LISTED tiers — positives first, then gaps. Numbered
  // when 2+ gaps exist (matches mockup 3.1 which numbers 3 items).
  for (const p of positives) lines.push(renderPositive(p.text));

  const numbered = gaps.length >= 2;
  for (let i = 0; i < gaps.length; i++) {
    lines.push(renderGap(gaps[i].text, numbered, i));
  }

  return { header, lines };
}
