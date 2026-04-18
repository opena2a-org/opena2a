import chalk from "chalk";

export type Verdict = "safe" | "warning" | "blocked" | "listed";

/**
 * Collapse the registry's verdict string variants into a normalized form.
 * Accepts: "safe", "passed", "warning", "warnings", "blocked", "failed", "listed".
 */
export function normalizeVerdict(verdict: string): string {
  switch (verdict) {
    case "safe":
    case "passed":
      return "safe";
    case "warning":
    case "warnings":
      return "warning";
    case "blocked":
    case "failed":
      return "blocked";
    case "listed":
      return "listed";
    default:
      return verdict;
  }
}

/**
 * Map a verdict string (or its variants) to its chalk color function.
 * Unknown verdicts render dim gray.
 */
export function verdictColor(verdict: string): (text: string) => string {
  const normalized = normalizeVerdict(verdict);
  switch (normalized) {
    case "safe":
      return chalk.green;
    case "warning":
      return chalk.yellow;
    case "blocked":
      return chalk.red;
    case "listed":
      return chalk.cyan;
    default:
      return chalk.gray;
  }
}
