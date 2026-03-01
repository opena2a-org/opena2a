import { bold, red, yellow, green, cyan, gray } from './colors.js';

export function severityColor(severity: string): (text: string) => string {
  switch (severity) {
    case 'critical': return red;
    case 'high': return red;
    case 'medium': return yellow;
    case 'low': return cyan;
    default: return gray;
  }
}

export function severityLabel(severity: string): string {
  return severityColor(severity)(severity.toUpperCase());
}

export function formatCount(count: number, label: string): string {
  if (count === 0) return green(`0 ${label}`);
  return bold(`${count} ${label}`);
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const mins = Math.floor(ms / 60000);
  const secs = Math.floor((ms % 60000) / 1000);
  return `${mins}m ${secs}s`;
}

export function table(rows: string[][], headers?: string[]): string {
  const allRows = headers ? [headers, ...rows] : rows;
  const colWidths = allRows[0].map((_, i) =>
    Math.max(...allRows.map(row => (row[i] ?? '').length))
  );

  const lines: string[] = [];
  for (let r = 0; r < allRows.length; r++) {
    const row = allRows[r];
    const cells = row.map((cell, i) => cell.padEnd(colWidths[i]));
    lines.push(cells.join('  '));
    if (r === 0 && headers) {
      lines.push(colWidths.map(w => '-'.repeat(w)).join('  '));
    }
  }

  return lines.join('\n');
}
