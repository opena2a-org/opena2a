/**
 * Match-with-allowlist helpers. Lifted from secretless/src/scan.ts so the
 * canonical "skip known-example credentials, keep real ones" contract lives
 * with the patterns themselves. PR 2 + PR 3 stop reimplementing this.
 */

import { KNOWN_EXAMPLE_KEYS, PLACEHOLDER_INDICATORS, type CredentialPattern } from './patterns.js';

/**
 * Demo-tier passwords that combine with localhost-bound DB connection strings
 * to mark a value as a tutorial fixture, not a real credential.
 *
 * Real prod credentials should never be values like `password123` AND bound to
 * `localhost`. The combination is the allowlist signal.
 */
const DEMO_PASSWORDS = new Set([
  'password',
  'password123',
  'secret',
  'admin',
  'root',
  'demo',
  'test',
  'changeme',
]);

function isLocalhostDemoConnectionString(value: string): boolean {
  const protoEnd = value.indexOf('://');
  if (protoEnd === -1) return false;
  const atIdx = value.lastIndexOf('@');
  if (atIdx === -1 || atIdx <= protoEnd + 3) return false;
  const userInfo = value.slice(protoEnd + 3, atIdx);
  const host = value.slice(atIdx + 1);
  // Anchored host check defeats `localhost.evil.com` bypass. Accepts IPv4
  // loopback `127.0.0.1`, IPv6 loopback `[::1]`, and the `localhost` literal.
  if (!/^(\[::1\]|localhost|127\.0\.0\.1)(:|\/|$)/i.test(host)) return false;
  const colonIdx = userInfo.indexOf(':');
  if (colonIdx === -1) return false;
  // Password compared case-insensitively — `Password123` in a tutorial fixture
  // is functionally the same demo password as `password123`.
  const password = userInfo.slice(colonIdx + 1).toLowerCase();
  return DEMO_PASSWORDS.has(password);
}

function isExampleInComment(line: string): boolean {
  const lineLC = line.toLowerCase();
  if (!lineLC.includes('example')) return false;
  if (lineLC.includes('//')) return true;
  if (lineLC.includes('#')) return true;
  if (lineLC.includes('/*')) return true;
  if (lineLC.includes('<!--')) return true;
  if (lineLC.includes('-->')) return true;
  if (lineLC.includes("'''")) return true;
  if (lineLC.includes('"""')) return true;
  // JSDoc continuation: line starts with optional whitespace then `*`.
  // Anchored so `x * y` (multiplication) does NOT match.
  if (/^\s*\*/.test(line)) return true;
  return false;
}

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
  if (KNOWN_EXAMPLE_KEYS.has(value)) return true;
  const lower = value.toLowerCase();
  if (PLACEHOLDER_INDICATORS.some(p => lower.includes(p))) return true;
  if (isLocalhostDemoConnectionString(value)) return true;
  if (isExampleInComment(line)) return true;
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
