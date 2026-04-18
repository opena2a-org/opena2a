import chalk from "chalk";

export type TrustLevel = 0 | 1 | 2 | 3 | 4;

const LEVEL_NAMES = ["Blocked", "Warning", "Listed", "Scanned", "Verified"] as const;

/**
 * Human name for a 0-4 trust level.
 */
export function trustLevelLabel(level: number): string {
  if (level >= 0 && level < LEVEL_NAMES.length) return LEVEL_NAMES[level];
  return `Unknown (${level})`;
}

/**
 * Chalk color for a trust level. Green for Scanned/Verified, yellow for
 * Warning/Listed, red for Blocked.
 */
export function trustLevelColor(level: number) {
  if (level >= 3) return chalk.green;
  if (level >= 1) return chalk.yellow;
  return chalk.red;
}

/**
 * `Blocked > Warning > Listed > Scanned > Verified` with the current level
 * highlighted in its color, others dim.
 */
export function trustLevelLegend(currentLevel: number): string {
  return LEVEL_NAMES.map((name, i) => {
    if (i === currentLevel) return trustLevelColor(i).bold(name);
    return chalk.dim(name);
  }).join(chalk.dim(" > "));
}

/**
 * Chalk color for a raw score value (0-100 scale).
 */
export function scoreColor(value: number): (text: string) => string {
  if (value >= 70) return chalk.green;
  if (value >= 40) return chalk.yellow;
  return chalk.red;
}
