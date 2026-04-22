/**
 * Not-found block — unified "package not found" output.
 *
 * Closes F5 from briefs/check-command-divergence.md: today the three CLIs
 * emit three different shapes for the same miss. This primitive gives them
 * one renderer.
 *
 * Renderer returns structured lines only — no chalk. The CLI owns color.
 */

export type NotFoundTone = "default" | "warning" | "critical" | "dim" | "good";

export interface NotFoundBlockInput {
  /** The package name the user typed (may include ecosystem prefix, e.g. "pip:requests"). */
  pkg: string;
  /** Ecosystem hint shown in the header, e.g. "npm", "pypi". */
  ecosystem?: string;
  /**
   * "Did you mean?" alternatives. Any source may supply these — registry fuzzy
   * match, local skill registry, on-disk package lookup. Empty / undefined and
   * the suggestions block is skipped entirely.
   */
  suggestions?: string[];
  /**
   * Optional skill-fallback CTA. HMA and opena2a-cli can resolve some names
   * as skills when npm misses; ai-trust cannot. When provided, renders
   * a targeted CTA pointing to the skill-capable CLI.
   */
  skillFallback?: { available: boolean; command: string };
  /**
   * Translated error hint for cases like `anthropic/code-review` being
   * mistaken for a git remote (F3 in the divergence brief). Passed through
   * verbatim when provided.
   */
  errorHint?: string;
}

export interface NotFoundBlockLine {
  /** Optional label column. Lines without a label render full-width. */
  label?: string;
  value: string;
  tone: NotFoundTone;
}

export interface RenderedNotFound {
  /** Header text, e.g. "Package not found: @anthropic/code-review (npm)". */
  header: { text: string; tone: NotFoundTone };
  /**
   * Body lines in render order. Contents:
   *   - optional errorHint line
   *   - "Did you mean?" header + one line per suggestion (when any)
   *   - skill-fallback CTA (when provided)
   * Empty when nothing to show beyond the header (caller falls through to
   * the generic not-found message).
   */
  lines: NotFoundBlockLine[];
}

export function renderNotFoundBlock(input: NotFoundBlockInput): RenderedNotFound {
  const { pkg, ecosystem, suggestions, skillFallback, errorHint } = input;

  const headerText = ecosystem ? `Package not found: ${pkg} (${ecosystem})` : `Package not found: ${pkg}`;
  const header = { text: headerText, tone: "critical" as NotFoundTone };

  const lines: NotFoundBlockLine[] = [];

  if (errorHint) {
    lines.push({ value: errorHint, tone: "warning" });
  }

  if (suggestions && suggestions.length > 0) {
    lines.push({ value: "Did you mean?", tone: "default" });
    for (const s of suggestions) {
      lines.push({ value: s, tone: "good" });
    }
  }

  if (skillFallback?.available) {
    lines.push({
      label: "Try",
      value: skillFallback.command,
      tone: "default",
    });
  }

  return { header, lines };
}
