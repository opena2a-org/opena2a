/**
 * Display-safety for names that came out of a scanned tree — file and
 * directory names, package names, excerpts of file content.
 *
 * Whoever wrote the scanned repository chose those names. Written straight
 * to a terminal, two things go wrong:
 *   - A line feed SPLITS the line, so a name can print a second line that
 *     reads like the tool's own output, or cut a copy-pasteable command off
 *     mid-quote.
 *   - An ESC byte controls the terminal: `ESC [ 2 J` clears the screen,
 *     `ESC [ 1 A` moves the cursor up over the report line describing the
 *     name, and an OSC sequence reaches the terminal's command channel. Bidi
 *     overrides and zero-width characters make the DISPLAYED name differ from
 *     the real one: U+202E followed by `gnp.elif_ngineb` reads as
 *     `benign_file.png`.
 *
 * So these characters are made VISIBLE rather than dropped. Dropping turns
 * two different names into one, and a shortened name in a report is a name
 * that does not exist. Escaping keeps each name on one line and keeps the
 * report a faithful description of what was found.
 *
 * The escape alphabet is `\n`, `\t`, `\r`, `\0`, `\e`, `\xHH`, `\uHHHH` and
 * `\u{…}`, the one hackmyagent and secretless-ai already print, so a name
 * renders the same in every CLI that uses this module.
 *
 * `sanitizeForTerminal` (terminal-safe.ts) is a different tool for a
 * different input: it STRIPS sequences from registry prose and keeps `\n`
 * and `\t` for layout. Use this module for a name, that one for a paragraph.
 *
 * Pure string functions: no chalk, so a caller colors the escaped result.
 */
import path from "node:path";

/**
 * The hazard class, as a regex source string, exported so a CLI that keeps
 * its own copy can assert it has not drifted.
 *
 * A CATEGORY, not a list, so it cannot fall behind one reporter at a time:
 *   - `\p{Cc}`: C0, DEL, C1.
 *   - `\p{Cf}`: every format character — the bidi marks, embeddings,
 *     overrides and isolates, the zero-width characters and joiners, the
 *     BOM, the soft hyphen, the assigned tag characters.
 *   - `\p{Zl}`, `\p{Zp}`: the two Unicode line separators.
 *   - The characters that render as nothing or as a blank without being Cc
 *     or Cf: the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0), the
 *     combining grapheme joiner (U+034F), the Khmer inherent vowels (U+17B4,
 *     U+17B5), the Mongolian free variation selectors and vowel separator
 *     (U+180B to U+180F) and the blank Braille pattern (U+2800).
 *   - The variation selectors U+FE00 to U+FE0D, wherever they appear.
 *   - All of plane 14, U+E0000 to U+EFFFF: the tag block, the supplementary
 *     variation selectors, and the unassigned runs `\p{Cf}` does not cover,
 *     which render as nothing as well (`a<U+E0200>b` prints as `ab`).
 *
 * One exemption: U+FE0E or U+FE0F FOLLOWING a pictograph chooses text or
 * emoji presentation, and the character it modifies is what the reader
 * sees. Escaping those would turn every emoji with a selector in a file name
 * into an escape for no gain. Those two are the only selectors that choose a
 * pictograph's presentation; any other selector after a pictograph is the
 * start of a hidden run, and U+FE0E or U+FE0F after anything else has
 * nothing visible to modify, so both are escaped.
 *
 * Written as a string of `\u` escapes rather than a regex literal: a literal
 * control byte inside a character class is invisible in every diff and every
 * editor that would review it.
 */
export const DISPLAY_HAZARD_SOURCE =
  "[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}\\u{115F}\\u{1160}\\u{3164}\\u{FFA0}\\u{FE00}-\\u{FE0D}\\u{E0000}-\\u{EFFFF}"
  + "\\u{034F}\\u{17B4}\\u{17B5}\\u{180B}-\\u{180F}\\u{2800}]"
  + "|(?<!\\p{Extended_Pictographic})[\\u{FE0E}\\u{FE0F}]";

const DISPLAY_HAZARD = new RegExp(DISPLAY_HAZARD_SOURCE, "gu");

/** Keyed by code point, for the same reason: no control characters in source. */
const NAMED: Record<number, string> = {
  0x00: "\\0",
  0x09: "\\t",
  0x0a: "\\n",
  0x0d: "\\r",
  0x1b: "\\e",
};

/**
 * One code point, rendered visibly. Astral code points take `\u{…}` braces:
 * U+E0041 is five hex digits where `\uHHHH` holds four, so without braces it
 * would read the same as U+E004 followed by `1`.
 */
function escapeCodePoint(code: number): string {
  const named = NAMED[code];
  if (named) return named;
  if (code <= 0xff) return `\\x${code.toString(16).padStart(2, "0")}`;
  return code <= 0xffff
    ? `\\u${code.toString(16).padStart(4, "0")}`
    : `\\u{${code.toString(16)}}`;
}

/**
 * Make invisible and terminal-controlling characters visible, so one
 * rendered line stays one line and says what is really there.
 *
 * Every replaced character maps to printable ASCII, so the result cannot
 * split a line, move the cursor, or change the terminal's state. Text with no
 * such characters is returned unchanged.
 *
 * For composed text — a fix line, a citation, an excerpt. A name printed on
 * its own takes `escapePathForDisplay`.
 */
export function escapeForDisplay(text: string): string {
  return text.replace(DISPLAY_HAZARD, (ch) => escapeCodePoint(ch.codePointAt(0) ?? 0));
}

/** True when `escapeForDisplay` would change `text`, i.e. what is shown is a rendering. */
export function hasDisplayHazard(text: string): boolean {
  DISPLAY_HAZARD.lastIndex = 0;
  return DISPLAY_HAZARD.test(text);
}

/**
 * The same class, escaped inside a serialized JSON document as `\uXXXX`.
 *
 * `JSON.stringify` escapes C0 and leaves DEL, C1, the bidi controls and the
 * Unicode line separators raw, so a `--json` document printed to a terminal
 * carries them straight from a name. A `\uXXXX` escape is lossless: any JSON
 * parser reads the real characters back.
 *
 * Applied to the serialized text, not the value. Outside a string literal a
 * `JSON.stringify` document holds only ASCII, so every match outside C0 lies
 * inside a string. A raw C0 match is the document's own indentation newline,
 * which is structure and stays. An astral code point becomes its surrogate
 * pair, the only form JSON has.
 */
export function escapeJsonDisplayHazards(json: string): string {
  return json.replace(DISPLAY_HAZARD, (ch) => {
    if (ch.charCodeAt(0) < 0x20) return ch;
    let escaped = "";
    for (let i = 0; i < ch.length; i++) {
      escaped += `\\u${ch.charCodeAt(i).toString(16).padStart(4, "0")}`;
    }
    return escaped;
  });
}

/**
 * A path with `/` between its parts on every platform.
 *
 * On Windows `\` is the separator and no name can hold it; escaped as a name
 * character it would be doubled before an escape letter, so `src\new.ts`
 * would print as `src\\new.ts`. On POSIX a backslash is a character a name
 * can hold, and turning it into `/` would name a different path. So only the
 * platform's own separator is replaced. `sep` is a parameter so both
 * platforms can be tested on either.
 */
function withSlashSeparators(p: string, sep: string): string {
  return sep === "/" ? p : p.split(sep).join("/");
}

const AMBIGUOUS_AFTER_BACKSLASH = new Set(["0", "t", "n", "r", "e", "x", "u", "\\"]);

/**
 * The same escaping for a BARE name, and one-to-one.
 *
 * `escapeForDisplay` alone renders a directory literally named `dir\nx`
 * (backslash, then `n`) exactly like one named `dir<LF>x`. A backslash only
 * needs escaping when it could be READ as one of the escapes above, so only
 * those are doubled: a backslash before `0`, `t`, `n`, `r`, `e`, `x`, `u`,
 * another backslash, or a character that is about to become an escape.
 * `a\b.txt` renders as itself and matches a citation of the same file;
 * `dir\nx` renders as `dir\\nx`. A Windows separator prints as `/` first.
 *
 * Doubling is only correct on a raw name. In composed text a backslash may
 * already be shell syntax or an escape this module produced, and doubling
 * there would change a correct command and grow on every pass — so composed
 * text takes `escapeForDisplay`.
 */
export function escapePathForDisplay(p: string, sep: string = path.sep): string {
  // Two passes, and the order matters. Doubling is decided per character
  // with a one-character lookahead; escaping is decided over the whole
  // string, because the pictograph exemption is a lookbehind that a
  // per-character test cannot see.
  const chars = [...withSlashSeparators(p, sep)];
  let doubled = "";
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    if (ch !== "\\") {
      doubled += ch;
      continue;
    }
    const next = chars[i + 1];
    // A trailing backslash cannot be read as an escape. A backslash before a
    // hazard is ambiguous whatever the exemption says, because the backslash
    // itself now stands between the pictograph and the selector.
    const ambiguous = next !== undefined
      && (AMBIGUOUS_AFTER_BACKSLASH.has(next) || hasDisplayHazard(next));
    doubled += ambiguous ? "\\\\" : "\\";
  }
  return escapeForDisplay(doubled);
}

/**
 * A name that cannot be printed as itself, escaped and quoted as one word:
 * `$'...'`, the shell's quoting for a string with escapes in it.
 *
 * A list prints `<path>: <reason>`. Escaped but bare, a name has no visible
 * end, so a `: ` inside it reads as that separator. Inside the quotes every
 * backslash is doubled and a single quote is written `\'`, so read left to
 * right, the first `'` that is not part of a `\'` ends the name.
 *
 * Only for a name that `hasDisplayHazard` flags, and never offered as a
 * command operand: it describes the name. A name that prints as itself is
 * quoted for pasting by the caller's own shell quoting.
 */
export function quotePathForDisplay(p: string, sep: string = path.sep): string {
  let body = "";
  for (const ch of withSlashSeparators(p, sep)) {
    body += ch === "\\" ? "\\\\" : ch === "'" ? "\\'" : ch;
  }
  return `$'${escapeForDisplay(body)}'`;
}

/**
 * An excerpt of a file's content, as lines to print one by one under the
 * caller's own prefix, each with its hazards escaped.
 *
 * A line break in an excerpt is one the reader should see, so it becomes a
 * new line under the tool's prefix rather than a `\n`; nothing the excerpt
 * prints can then pass for the tool's own output. A carriage return that
 * does not end a line would move the cursor back over the prefix, so it is
 * escaped like any other control character.
 */
export function excerptLinesForDisplay(text: string): string[] {
  return text.split(/\r?\n/).map(escapeForDisplay);
}
