import chalk from "chalk";

const DIVIDER_WIDTH = 62;

/**
 * Section divider. With a label: `── Findings ──────────────`.
 * Without a label: a plain horizontal rule.
 */
export function divider(label?: string): string {
  if (label) {
    const pad = Math.max(1, 56 - label.length);
    return `\n  ${chalk.dim("\u2500\u2500")} ${chalk.bold(label)} ${chalk.dim("\u2500".repeat(pad))}`;
  }
  return `  ${chalk.dim("\u2500".repeat(DIVIDER_WIDTH))}`;
}
