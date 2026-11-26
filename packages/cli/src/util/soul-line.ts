/**
 * How a soul-file line is compared with a line `harden-soul` writes.
 *
 * Runs of whitespace become one space and the ends are trimmed; the result is
 * hashed with SHA-256, so the generated set holds digests and not the
 * template prose (which other scanners would read as instructions). Two lines
 * match only when their normalised text is identical. Shared by the scanner
 * and by the script that builds harden-soul-lines.ts.
 */
import { createHash } from 'node:crypto';

export function normaliseSoulLine(line: string): string {
  return line.replace(/\s+/g, ' ').trim();
}

/** SHA-256 hex digest of the normalised line. */
export function soulLineDigest(line: string): string {
  return createHash('sha256').update(normaliseSoulLine(line), 'utf8').digest('hex');
}
