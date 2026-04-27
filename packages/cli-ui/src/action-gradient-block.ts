/**
 * Action gradient block — renders the rule-engine's `nextSteps[]`
 * verbatim under "Next".
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§5.2).
 *
 * The rule engine emits a deterministic ordered list of `NextStep`
 * entries with `weight: 'primary' | 'secondary'`. The renderer
 * column-aligns the labels (so `Install confidently:` and
 * `Pin to current:` line up across rows) and renders one line per
 * step. The first `primary` carries the headline tone; secondary
 * entries render at default tone.
 *
 * Step labels, commands, and URLs are sanitized via
 * `sanitizeForTerminal` — registry-sourced rotation URLs / install
 * commands are untrusted and could embed ANSI / OSC-8 / control bytes
 * that would otherwise spoof the displayed action.
 */
import { sanitizeForTerminal } from "./terminal-safe.js";

/**
 * Local mirror of `NextStep` from check-core. Defined here so cli-ui
 * stays dep-light. Structural typing means the registry-sourced
 * narrative entries pass through unchanged.
 */
export interface NextStepLike {
  weight: "primary" | "secondary";
  label: string;
  command?: string;
  url?: string;
}

export type ActionGradientTone =
  | "default"
  | "good"
  | "warning"
  | "critical"
  | "dim";

/**
 * Verdict tier influences the primary tone — VERIFIED is good (green),
 * BLOCKED is critical (red), LISTED / unscanned are default. NOT_FOUND
 * also uses default; the orchestrator decides whether to render the
 * NOT_FOUND-specific "Next" block via this function or a separate one.
 */
export type ActionGradientTier =
  | "VERIFIED"
  | "LISTED"
  | "LISTED_UNSCANNED"
  | "BLOCKED"
  | "NOT_FOUND";

export interface ActionGradientInput {
  tier: ActionGradientTier;
  steps: NextStepLike[];
}

export interface ActionGradientLine {
  /** Pre-aligned row, e.g. `Install confidently:  opena2a install ...`. */
  text: string;
  tone: ActionGradientTone;
}

export interface RenderedActionGradient {
  lines: ActionGradientLine[];
}

function primaryToneFor(tier: ActionGradientTier): ActionGradientTone {
  switch (tier) {
    case "VERIFIED":
      return "good";
    case "BLOCKED":
      return "critical";
    case "LISTED":
    case "LISTED_UNSCANNED":
    case "NOT_FOUND":
    default:
      return "default";
  }
}

/**
 * Compose the right-hand value for a step. `command` and `url` are
 * mutually exclusive in practice, but if both are set we prefer the
 * command (more actionable). Returns empty string when neither is set
 * — the renderer drops the colon-and-padding suffix in that case.
 */
function stepValue(step: NextStepLike): string {
  if (step.command && step.command.length > 0) {
    return sanitizeForTerminal(step.command);
  }
  if (step.url && step.url.length > 0) {
    return sanitizeForTerminal(step.url);
  }
  return "";
}

/**
 * Compute the label-column width — longest "<label>:" across all rows
 * + 2 spaces. Caps at 24 to keep narrow terminals readable; longer
 * labels overflow gracefully (the value column starts after the
 * single-space separator).
 */
function computeLabelWidth(steps: NextStepLike[]): number {
  let max = 0;
  for (const s of steps) {
    if (s.label.length > max) max = s.label.length;
  }
  // "<label>:" + 2 spaces, capped.
  return Math.min(max + 3, 24);
}

function padLabel(label: string, width: number): string {
  const withColon = `${label}:`;
  if (withColon.length >= width) return `${withColon} `;
  return withColon + " ".repeat(width - withColon.length);
}

export function renderActionGradientBlock(
  input: ActionGradientInput,
): RenderedActionGradient {
  const { tier, steps } = input;

  if (steps.length === 0) {
    return { lines: [] };
  }

  const width = computeLabelWidth(steps);
  const headlineTone = primaryToneFor(tier);
  let primarySeen = false;

  const lines: ActionGradientLine[] = [];
  for (const step of steps) {
    const safeLabel = sanitizeForTerminal(step.label);
    const value = stepValue(step);
    let row: string;
    if (value.length === 0) {
      // No command / URL — render label only without trailing colon.
      // (Mockup 3.6: "Stop:  Do NOT install" — but "Do NOT install"
      // is the label-only directive that ships as `command`. If a
      // step has truly no value we strip the colon.)
      row = safeLabel;
    } else {
      row = `${padLabel(safeLabel, width)}${value}`;
    }

    let tone: ActionGradientTone;
    if (step.weight === "primary" && !primarySeen) {
      tone = headlineTone;
      primarySeen = true;
    } else if (step.weight === "primary") {
      tone = "default";
    } else {
      tone = "default";
    }

    lines.push({ text: row, tone });
  }

  return { lines };
}
