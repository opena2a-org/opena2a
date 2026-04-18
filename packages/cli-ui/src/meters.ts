import chalk from "chalk";

const METER_WIDTH = 20;
const MINI_METER_WIDTH = 8;

function meterColor(value: number) {
  if (value >= 70) return chalk.green;
  if (value >= 40) return chalk.yellow;
  return chalk.red;
}

/**
 * Full-width score meter: `━━━━━━━━━━━━━━━━━━━━ 87/100`
 * Green >=70, yellow >=40, red below.
 */
export function scoreMeter(value: number, max: number = 100): string {
  const pct = Math.round((value / max) * METER_WIDTH);
  const color = meterColor(value);
  const filled = "\u2501".repeat(pct);
  const empty = "\u2501".repeat(METER_WIDTH - pct);
  return `${color(filled)}${chalk.dim(empty)} ${color.bold(String(value))}${chalk.dim(`/${max}`)}`;
}

/**
 * Compact meter for table cells: `━━━━━━━━ 87`
 */
export function miniMeter(value: number, max: number = 100): string {
  const pct = Math.round((value / max) * MINI_METER_WIDTH);
  const color = meterColor(value);
  const filled = "\u2501".repeat(pct);
  const empty = "\u2501".repeat(MINI_METER_WIDTH - pct);
  return `${color(filled)}${chalk.dim(empty)} ${color.bold(String(value))}`;
}
