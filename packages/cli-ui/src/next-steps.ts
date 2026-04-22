/**
 * Next Steps block — per-CLI CTA injection with consistent rendering.
 *
 * Closes F7 from briefs/check-command-divergence.md: the three CLIs today
 * emit different (or missing) Next Steps blocks. Labels must stay identical
 * across CLIs so users build one mental model; commands differ because each
 * CLI binary is different (`hackmyagent secure` vs `opena2a scan`).
 *
 * Callers pass their own command strings. This renderer owns bullet style,
 * alignment, and primary-CTA emphasis. No chalk — CLI applies color via tone.
 */

export type NextStepsTone = "default" | "good" | "dim";

export interface NextStepsCta {
  /** Short action label, e.g. "Full scan", "Contribute findings". */
  label: string;
  /** Runnable command, e.g. "hackmyagent secure .". */
  command: string;
  /**
   * True for the primary recommended action. At most one should be primary;
   * if multiple are flagged, the first wins (renderer doesn't enforce beyond
   * that — this is just visual emphasis).
   */
  primary?: boolean;
}

export interface NextStepsInput {
  ctas: NextStepsCta[];
}

export interface NextStepsLine {
  /** `→` for primary, `•` for everything else. */
  bullet: string;
  label: string;
  command: string;
  tone: NextStepsTone;
}

export interface RenderedNextSteps {
  lines: NextStepsLine[];
}

const PRIMARY_BULLET = "→"; // →
const DEFAULT_BULLET = "•"; // •

export function renderNextSteps(input: NextStepsInput): RenderedNextSteps {
  const { ctas } = input;
  let primaryClaimed = false;
  const lines: NextStepsLine[] = ctas.map((cta) => {
    const isPrimary = cta.primary === true && !primaryClaimed;
    if (isPrimary) primaryClaimed = true;
    return {
      bullet: isPrimary ? PRIMARY_BULLET : DEFAULT_BULLET,
      label: cta.label,
      command: cta.command,
      tone: isPrimary ? "good" : "default",
    };
  });
  return { lines };
}
