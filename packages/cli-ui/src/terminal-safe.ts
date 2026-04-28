/**
 * Terminal-safety helper — strip ANSI escape sequences and C0/C1
 * control bytes from caller-supplied strings before they enter
 * rendered output.
 *
 * Threat model: registry-sourced narrative fields (`summary`,
 * `behaviorDescription`, `misuseNarrative`, `pathScope`, `network`,
 * `persistence`, `auth`, `mcp.tools[].description`, finding
 * `description`/`fix`, `nextStep.command`, etc.) are written by
 * untrusted publishers via `secure --publish`. A malicious record
 * could embed:
 *   - CSI sequences (`\x1b[2J\x1b[H`) to clear the screen and hide
 *     prior findings (audit / log-tampering risk).
 *   - OSC-8 hyperlinks (`\x1b]8;;evil://x\x07Click\x1b]8;;\x07`) to
 *     spoof rotation / install URLs.
 *   - Standalone control bytes (`\r`, `\x07` bell, NULs) to confuse
 *     piping consumers that expect newline-delimited output.
 *
 * Strip all `\x1b…` sequences (CSI, OSC, lone Esc) plus C0 control
 * bytes 0x00-0x08 / 0x0b-0x1f and 0x7f (DEL). Preserve `\n` (0x0a)
 * and `\t` (0x09); the renderer relies on those for layout.
 *
 * Pure rendering library — this is the only place the threat is
 * mitigated; downstream chalk application by the CLI is applied to
 * the whole sanitized line, so caller chalk still works.
 */

// Build the pattern with explicit `\x1b` escapes (no literal ESC bytes
// in source — keeps the file editor-safe). Arms in order:
//   1. CSI: ESC [ <digits/;/?>* <final byte 0x40-0x7e>
//   2. OSC: ESC ] <any-non-terminator>* (BEL=0x07 | ST=ESC \)
//   3. Lone ESC followed by an optional non-printable
//   4. C0 controls except \t (0x09) and \n (0x0a), plus DEL (0x7f)
const TERMINAL_HOSTILE = new RegExp(
  [
    "\\x1b\\[[0-9;?]*[\\x40-\\x7e]",
    "\\x1b\\][^\\x07\\x1b]*(?:\\x07|\\x1b\\\\)",
    "\\x1b[^\\x40-\\x7e]?",
    "[\\x00-\\x08\\x0b-\\x1f\\x7f]",
  ].join("|"),
  "g",
);

export function sanitizeForTerminal(s: string | undefined | null): string {
  if (s === undefined || s === null) return "";
  if (s.length === 0) return s;
  return s.replace(TERMINAL_HOSTILE, "");
}

/**
 * Sanitize each entry in a string array. Convenience wrapper for
 * fields like `activationPhrases[]`, `externalServices[]`,
 * `sideEffects[]` where the array itself is trusted (length comes
 * from the registry record) but the elements are untrusted strings.
 */
export function sanitizeArray(arr: readonly string[] | undefined): string[] {
  if (!arr) return [];
  return arr.map(sanitizeForTerminal);
}
