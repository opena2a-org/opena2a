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

/** Position of the earliest PLACEHOLDER_INDICATORS entry in `lower`, or -1. */
function placeholderIndex(lower: string): number {
  let at = -1;
  for (const p of PLACEHOLDER_INDICATORS) {
    const i = lower.indexOf(p);
    if (i !== -1 && (at === -1 || i < at)) at = i;
  }
  return at;
}

const ANCHORED = new WeakMap<RegExp, RegExp>();

/** `regex` wrapped as `^(?:…)$`, so it must cover a string in full. */
function anchored(regex: RegExp): RegExp {
  let re = ANCHORED.get(regex);
  if (!re) {
    re = new RegExp(`^(?:${regex.source})$`, regex.flags.replace(/[gy]/g, ''));
    ANCHORED.set(regex, re);
  }
  return re;
}

/**
 * True when the placeholder word at `at` follows a value that is a complete
 * match of `pattern` on its own: `xoxb-…-<24 characters>sample`. A pattern
 * whose body is a floor rather than a fixed length takes the word into the
 * match, and a whole-value placeholder test would then drop the token in
 * front of it, which is the token a `.replace('sample', '')` at runtime
 * turns back into the live one. The part before the word must pass every
 * other allowlist rule (known example, low entropy, localhost demo) itself.
 *
 * For a pattern whose body is a fixed length followed by an open run
 * (`[a-zA-Z0-9]{24}[a-zA-Z0-9]*`: slack and the GitHub `ghp_`, `gho_`, `ghs_`
 * and `ghu_` tokens) the token may end inside the word: when the word begins
 * inside the fixed length and runs past it (`xoxb-…-<23 characters>x` then
 * `xx`, `ghp_<34 characters>sa` then `mple`), the part before the word is
 * short of a complete match, while the pinned length slack, `ghp_`, `gho_`
 * and `ghs_` had before stopped the match at the token. So for such a
 * pattern the token is the shortest prefix of the value that is a complete
 * match on its own and ends at or after the word's start; a prefix that
 * already holds a complete placeholder word is never the token. Every other
 * pattern takes the part before the word as the token: searching past the
 * word's start there would take the word's first characters as the secret
 * of a pattern whose last part has a small floor
 * (`…/api/webhooks/<id>/your_webhook_token`).
 *
 * Needs the pattern, so it applies only when a caller passes one, and only
 * to value-only patterns: a name-gated match's value is group 1, which the
 * anchored pattern (name included) cannot match on its own.
 */
function isPlaceholderGluedToValue(
  line: string,
  value: string,
  at: number,
  match: RegExpMatchArray,
  pattern: Pick<CredentialPattern, 'regex'> | undefined,
): boolean {
  if (!pattern || match[1] !== undefined || at <= 0) return false;
  const re = anchored(pattern.regex);
  const last = /\{\d+\}\[[^\]]+\]\*$/.test(pattern.regex.source) ? value.length : at;
  for (let end = at; end <= last; end++) {
    const head = value.slice(0, end);
    if (end > at && placeholderIndex(head.toLowerCase()) !== -1) return false;
    const headMatch = re.exec(head);
    if (headMatch) return !isKnownExample(line, headMatch);
  }
  return false;
}

/**
 * Check if a matched credential is a known example or placeholder.
 * Returns true if the match should be excluded from results.
 *
 * Exported so any scanner can apply the same allowlist. Prevents scanners
 * from blocking docs that legitimately reference public example keys like
 * AKIAIOSFODNN7EXAMPLE.
 *
 * Every rule reads the matched value. The rest of `line` is not read: a
 * comment beside the value (`// example`, `# example`, `<!-- example -->`)
 * is text the author of the line controls, so it never marks a full-format
 * token as an example.
 *
 * `pattern` is optional. When given, a placeholder word that directly follows
 * a value which is a complete match of the pattern on its own does not mark
 * that value as a placeholder (see {@link isPlaceholderGluedToValue}).
 * Without it the placeholder test runs on the whole value, as before.
 */
export function isKnownExample(
  line: string,
  match: RegExpMatchArray,
  pattern?: Pick<CredentialPattern, 'regex'>,
): boolean {
  // Prefer the captured value (group 1) when a pattern is name-gated — its
  // match[0] is "name = value", so the example/placeholder checks must run on
  // the value, not the whole match. Value-only patterns have no group 1 and
  // fall back to match[0] unchanged.
  const value = match[1] ?? match[0];
  if (KNOWN_EXAMPLE_KEYS.has(value)) return true;
  const lower = value.toLowerCase();
  const at = placeholderIndex(lower);
  if (at !== -1 && !isPlaceholderGluedToValue(line, value, at, match, pattern)) return true;
  // Low-entropy filler keyed by a credential name (e.g. `aws_secret_access_key
  // = "0000…"` / `DEADBEEF…`): a real ≥20-char secret never has so few distinct
  // characters (random base64 of a 40-char key has ~30+), so this can't suppress
  // a genuine key. Guards name-gated patterns whose value alone can't be trusted
  // by shape.
  if (value.length >= 20 && new Set(value).size <= 6) return true;
  if (isLocalhostDemoConnectionString(value)) return true;
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
    if (!isKnownExample(line, m, pattern)) return m;
  }
  return null;
}
