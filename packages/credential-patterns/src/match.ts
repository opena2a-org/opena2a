/**
 * Match-with-allowlist helpers. Lifted from secretless/src/scan.ts so the
 * canonical "skip known-example credentials, keep real ones" contract lives
 * with the patterns themselves. PR 2 + PR 3 stop reimplementing this.
 */

import { KNOWN_EXAMPLE_KEYS, PLACEHOLDER_INDICATORS, type CredentialPattern } from './patterns.js';

/**
 * Check if a matched credential is a known example or placeholder.
 * Returns true if the match should be excluded from results.
 *
 * Exported so any scanner can apply the same allowlist. Prevents scanners
 * from blocking docs that legitimately reference public example keys like
 * AKIAIOSFODNN7EXAMPLE.
 */
export function isKnownExample(line: string, match: RegExpMatchArray): boolean {
  const value = match[0];
  // Check exact known example keys
  if (KNOWN_EXAMPLE_KEYS.has(value)) return true;
  // Check placeholder indicators (case-insensitive)
  const lower = value.toLowerCase();
  if (PLACEHOLDER_INDICATORS.some(p => lower.includes(p))) return true;
  // Check if the line contains a comment marking it as an example
  const lineLC = line.toLowerCase();
  if (lineLC.includes('example') && (lineLC.includes('//') || lineLC.includes('#'))) {
    if (lineLC.includes('example') || lineLC.includes('placeholder') || lineLC.includes('fake')) return true;
  }
  return false;
}

/**
 * Return the first match in `line` for `pattern.regex` that is NOT a known
 * example, or null if every match is an example (or there are no matches).
 *
 * For /g regexes this iterates all matches via matchAll so that a known
 * example of a given pattern on a line does not shadow a real credential
 * of the same pattern later on that line. Non-global regexes fall back to
 * a single match check.
 */
export function findRealMatch(line: string, pattern: CredentialPattern): RegExpMatchArray | null {
  // matchAll requires /g. Promote non-/g patterns so we iterate EVERY match on
  // the line — otherwise a known-example match at position 0 would shadow a
  // real credential of the same pattern later on the same line.
  const globalRegex = pattern.regex.flags.includes('g')
    ? pattern.regex
    : new RegExp(pattern.regex.source, pattern.regex.flags + 'g');
  globalRegex.lastIndex = 0;
  for (const m of line.matchAll(globalRegex)) {
    if (!isKnownExample(line, m)) return m;
  }
  return null;
}
