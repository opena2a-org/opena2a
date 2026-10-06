import chalk from "chalk";

export type Verdict = "safe" | "warning" | "blocked" | "listed";

/**
 * A check's own verdict: it held ("pass"), it did not hold ("fail"), or no
 * verdict could be reached ("unverified"). Kept apart from the registry
 * family so the printed word stays the one the check reported.
 */
export type CheckVerdict = "pass" | "fail" | "unverified";

/**
 * Collapse the registry's verdict string variants into a normalized form.
 * Accepts: "safe", "passed", "warning", "warnings", "blocked", "failed", "listed".
 * The check family ("pass", "fail", "unverified") is returned unchanged.
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
    case "pass":
      return chalk.green;
    case "warning":
    case "unverified":
      return chalk.yellow;
    case "blocked":
    case "fail":
      return chalk.red;
    case "listed":
      return chalk.cyan;
    default:
      return chalk.gray;
  }
}
