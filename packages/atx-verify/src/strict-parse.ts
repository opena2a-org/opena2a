/**
 * Strict pre-parse for ATX credentials: rejects a credential that carries a
 * duplicate object member at ANY depth, where "duplicate" is judged under the
 * field folding a lenient consumer's JSON parser would apply.
 *
 * Every ATX field feeds a signed canonical form (the v1.1 JCS(TBS) projection,
 * the v1.0 pipe fields), so there is no layer with sanctioned RFC 7519
 * last-wins semantics — a duplicate member anywhere in the credential is the
 * RFC 8259 §4 first-wins/last-wins parser-divergence smuggling split and MUST
 * be rejected before any field is interpreted. This mirrors the strict parse
 * in the reference verifiers (atx-conformance `verifiers/go`,
 * `verifiers/python`), `opena2a-registry/pkg/atcverify`, and the Java SDK's
 * `AtxStrictParse` (agent-identity-management).
 *
 * Folding matters because a lenient struct-mapping parser (Go's encoding/json)
 * collapses a case-variant pair like `{"trustLevel":9,"TRUSTLEVEL":1}` to one
 * field last-wins. `JSON.parse` itself is case-sensitive but last-wins on
 * exact duplicates, so the two smuggle shapes land on different parsers; the
 * fold-scan catches both in a single pass.
 *
 * The scan runs on the RAW TEXT with a hand-rolled tokenizer: a reviver (or
 * any post-`JSON.parse` inspection) sees objects whose duplicates are already
 * collapsed. The tokenizer decodes string escapes in member names before
 * folding — `"trustLevel"` and `"trustLevel"` are the same member to
 * `JSON.parse`, so they must collide here too. It is iterative (explicit
 * frame stack, no recursion), so deep input cannot overflow the JS call stack;
 * nesting is additionally bounded at {@link MAX_SCAN_DEPTH} open containers.
 *
 * Unlike the Go reference verifier — whose scan silently abandons over-deep
 * input because `encoding/json.Unmarshal` enforces the same 10000-depth cap
 * right behind it — this scan REJECTS over-deep input itself: `JSON.parse`
 * has no fixed nesting cap, so an abandoned scan would leave members below
 * the abandonment depth unscanned while `JSON.parse` still reads them. The
 * resulting accept-set matches Go's scan+Unmarshal combination exactly.
 */

/**
 * Maximum number of simultaneously open containers (objects/arrays) the scan
 * accepts. Matches Go `encoding/json`'s maxNestingDepth (10000), which is what
 * the reference verifier's accept-set is bounded by; deeper input rejects as
 * malformed. (The Java SDK sits at Jackson's default of 1000 — stricter, on
 * inputs no honest credential produces.)
 */
export const MAX_SCAN_DEPTH = 10000;

/**
 * Controlled failure of the strict parse: the input is not JSON this scan can
 * vouch for (malformed, truncated, trailing content, or nested beyond
 * {@link MAX_SCAN_DEPTH}). `LocalAtxVerifier.verifyCredential` maps it to a
 * MALFORMED rejection; callers using {@link firstDuplicateMember} directly
 * must catch it.
 */
export class StrictParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StrictParseError';
  }
}

/**
 * Folds a JSON member name the way a lenient JSON-to-struct parser folds field
 * names: ASCII letters lowercased, plus the only two non-ASCII code points
 * that fold onto ASCII (Kelvin sign U+212A -> k, long s U+017F -> s); any
 * other code point via its simple (1:1) lowercase mapping, matching Go's
 * `unicode.ToLower` in the reference verifier's `foldKey` and Java's
 * `Character.toLowerCase`. (The Python reference's `str.lower()` diverges from
 * all three on exotic code points like U+0130 — an acknowledged upstream
 * outlier on names no honest credential produces.) Two names with the same
 * fold key are the same field to such a parser, so treating them as a
 * duplicate here catches the case-variant collapse. Real ATX member names are
 * ASCII, so the fold is exact on every honest credential.
 */
export function foldKey(name: string): string {
  let out = '';
  for (const ch of name) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0x41 && cp <= 0x5a) {
      out += String.fromCharCode(cp + 0x20);
    } else if (cp === 0x212a) {
      out += 'k'; // Kelvin sign
    } else if (cp === 0x017f) {
      out += 's'; // Latin small letter long s
    } else if (cp === 0x0130) {
      // Latin capital I with dot above: its SIMPLE lowercase is "i" (what Go
      // unicode.ToLower and Java Character.toLowerCase produce). JS
      // toLowerCase applies the FULL mapping "i̇" — the one unconditional
      // multi-code-point lowercase in Unicode — which would diverge from the
      // reference fold.
      out += 'i';
    } else if (cp < 0x80) {
      out += ch;
    } else {
      out += ch.toLowerCase();
    }
  }
  return out;
}

/** Raw-text span of a JSON value: `text.slice(start, end)` is the value. */
export interface ValueSpan {
  start: number;
  end: number;
}

interface ScanOptions {
  /** Detect fold-colliding duplicate members and abort with the second name. */
  checkDuplicates: boolean;
  /**
   * When the scanned value is an object, capture the raw span of this
   * top-level member's value (used by the conformance tests to extract
   * credential bytes verbatim, duplicates preserved).
   */
  spanMember?: string;
}

interface ScanResult {
  dup: string | null;
  span: ValueSpan | null;
}

/**
 * Scans raw ATX credential JSON for a member name that collides — under field
 * folding — with an earlier member of the same object, at any depth, and
 * returns the first such name. Returns `null` when the credential has no
 * duplicate members.
 *
 * A `null` return does NOT certify well-formedness: the scan is lax on scalar
 * tokens (`{"a":truex}` scans clean), so callers using this directly must
 * still `JSON.parse` — exactly what `verifyCredential` does. The laxness
 * cannot hide a duplicate, because the scalar character set contains no
 * structural characters.
 *
 * @throws StrictParseError if the text is structurally malformed (bad
 *     strings/escapes, mismatched or misplaced punctuation, trailing content)
 *     or exceeds {@link MAX_SCAN_DEPTH}; the caller surfaces that as a
 *     MALFORMED rejection.
 */
export function firstDuplicateMember(credentialJson: string): string | null {
  return new Scanner(credentialJson).scan({ checkDuplicates: true }).dup;
}

/**
 * Returns the raw-text span of a top-level object member's value, scanned with
 * the same tokenizer as {@link firstDuplicateMember} (duplicates tolerated, so
 * the strict-parse fixtures' credential bytes survive extraction verbatim).
 * Test helper — mirrors the Java conformance test's `rawAtxBytes`. Returns
 * `null` when the member is absent or the top-level value is not an object.
 *
 * @throws StrictParseError if the text is not a single well-formed JSON value.
 */
export function topLevelMemberSpan(text: string, member: string): ValueSpan | null {
  return new Scanner(text).scan({ checkDuplicates: false, spanMember: member }).span;
}

/** One open container on the scan stack. */
interface Frame {
  isObject: boolean;
  /** foldKey -> first raw (decoded) member name; null when not dup-checking or an array. */
  seen: Map<string, string> | null;
  /** Close of this frame ends the span capture. */
  captureEnd: boolean;
}

class Scanner {
  private i = 0;

  constructor(private readonly text: string) {}

  scan(opts: ScanOptions): ScanResult {
    this.skipWs();
    if (this.atEnd()) {
      throw new StrictParseError('empty credential');
    }
    const result = this.scanValue(opts);
    if (result.dup !== null) {
      return result; // abort-unwind: report immediately, mirror Go/Java
    }
    this.skipWs();
    if (!this.atEnd()) {
      this.fail('unexpected trailing content');
    }
    return result;
  }

  /**
   * Consumes exactly one JSON value iteratively. Two-phase loop: the outer
   * `value` phase consumes a value's first token (pushing a frame for
   * containers), the inner `unwind` phase consumes `,`-continuations and
   * container closes until another value is expected or the whole value ends.
   */
  private scanValue(opts: ScanOptions): ScanResult {
    const frames: Frame[] = [];
    let span: ValueSpan | null = null;
    let spanStart = -1;
    // Set when the just-consumed member name is the span target: the next
    // value scanned is the one to capture.
    let capturePending = false;

    const popFrame = (): void => {
      const f = frames.pop()!;
      if (f.captureEnd) {
        span = { start: spanStart, end: this.i };
      }
    };

    // Scans `"name" <ws> :` (cursor on the opening quote), dup-checks the
    // decoded name against the enclosing object frame, and arms span capture
    // when it matches the target. Returns the colliding name, or null.
    const memberName = (): string | null => {
      if (this.atEnd() || this.text[this.i] !== '"') {
        this.fail('expected member name');
      }
      const name = this.scanString(true);
      const top = frames[frames.length - 1];
      if (top.seen !== null) {
        const fk = foldKey(name);
        if (top.seen.has(fk)) {
          return name;
        }
        top.seen.set(fk, name);
      }
      this.skipWs();
      if (this.atEnd() || this.text[this.i] !== ':') {
        this.fail("expected ':' after member name");
      }
      this.i++;
      capturePending = opts.spanMember !== undefined && frames.length === 1 && name === opts.spanMember;
      return null;
    };

    value: for (;;) {
      this.skipWs();
      if (this.atEnd()) {
        this.fail('unexpected end of input');
      }
      const c = this.text[this.i];
      const valueStart = this.i;
      const capture = capturePending;
      capturePending = false;

      if (c === '{' || c === '[') {
        if (frames.length >= MAX_SCAN_DEPTH) {
          this.fail(`nesting exceeds ${MAX_SCAN_DEPTH} levels`);
        }
        this.i++;
        const isObject = c === '{';
        frames.push({
          isObject,
          seen: isObject && opts.checkDuplicates ? new Map() : null,
          captureEnd: capture,
        });
        if (capture) {
          spanStart = valueStart;
        }
        this.skipWs();
        if (!this.atEnd() && this.text[this.i] === (isObject ? '}' : ']')) {
          this.i++;
          popFrame();
          // fall through to unwind
        } else if (isObject) {
          const dup = memberName();
          if (dup !== null) {
            return { dup, span };
          }
          continue value;
        } else {
          continue value;
        }
      } else if (c === '"') {
        this.scanString(false);
        if (capture) {
          span = { start: valueStart, end: this.i };
        }
      } else {
        this.scanScalarToken();
        if (capture) {
          span = { start: valueStart, end: this.i };
        }
      }

      // unwind: a value just completed.
      for (;;) {
        if (frames.length === 0) {
          return { dup: null, span };
        }
        this.skipWs();
        if (this.atEnd()) {
          this.fail('unexpected end of input');
        }
        const top = frames[frames.length - 1];
        const ch = this.text[this.i];
        if (ch === ',') {
          this.i++;
          if (top.isObject) {
            this.skipWs();
            const dup = memberName();
            if (dup !== null) {
              return { dup, span };
            }
          }
          continue value;
        }
        if (ch === (top.isObject ? '}' : ']')) {
          this.i++;
          popFrame();
          continue;
        }
        this.fail(`unexpected character '${ch}'`);
      }
    }
  }

  /**
   * Scans a JSON string (cursor on the opening quote; on return, past the
   * closing quote). Escape sequences are validated always and DECODED when
   * `decode` is set — member-name comparison must happen on decoded names,
   * exactly as `JSON.parse` (and Go's Decoder.Token, Jackson's currentName)
   * produce them: `"trustLevel"` IS `"trustLevel"`. `\uXXXX` appends the
   * raw UTF-16 code unit, so surrogate pairs (and lone surrogates) combine the
   * same way `JSON.parse` combines them.
   */
  private scanString(decode: boolean): string {
    const t = this.text;
    this.i++; // opening quote
    let out = '';
    for (;;) {
      if (this.i >= t.length) {
        this.fail('unterminated string');
      }
      const c = t.charCodeAt(this.i);
      if (c === 0x22) {
        this.i++;
        return out;
      }
      if (c === 0x5c) {
        this.i++;
        if (this.i >= t.length) {
          this.fail('unterminated string escape');
        }
        const e = t[this.i];
        this.i++;
        switch (e) {
          case '"':
          case '\\':
          case '/':
            if (decode) out += e;
            break;
          case 'b':
            if (decode) out += '\b';
            break;
          case 'f':
            if (decode) out += '\f';
            break;
          case 'n':
            if (decode) out += '\n';
            break;
          case 'r':
            if (decode) out += '\r';
            break;
          case 't':
            if (decode) out += '\t';
            break;
          case 'u': {
            if (this.i + 4 > t.length) {
              this.fail('truncated \\u escape');
            }
            const hex = t.slice(this.i, this.i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
              this.fail('invalid \\u escape');
            }
            if (decode) out += String.fromCharCode(parseInt(hex, 16));
            this.i += 4;
            break;
          }
          default:
            this.fail(`invalid escape '\\${e}'`);
        }
      } else if (c < 0x20) {
        this.fail('unescaped control character in string');
      } else {
        if (decode) out += t[this.i];
        this.i++;
      }
    }
  }

  /**
   * Consumes a scalar token (number / true / false / null) lazily: the exact
   * grammar is `JSON.parse`'s to enforce afterwards; here it only matters that
   * the token's SPAN is right. The accepted character set contains no
   * structural characters, so a lax scalar can never swallow a brace, bracket,
   * quote, comma, or colon — and junk like `truex` still fails, either at the
   * unwind phase or at `JSON.parse`.
   */
  private scanScalarToken(): void {
    const t = this.text;
    const start = this.i;
    while (this.i < t.length) {
      const c = t[this.i];
      if (
        (c >= '0' && c <= '9') ||
        (c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        c === '+' ||
        c === '-' ||
        c === '.'
      ) {
        this.i++;
      } else {
        break;
      }
    }
    if (this.i === start) {
      this.fail(`unexpected character '${t[start]}'`);
    }
  }

  private skipWs(): void {
    const t = this.text;
    while (this.i < t.length) {
      const c = t.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
        this.i++;
      } else {
        return;
      }
    }
  }

  private atEnd(): boolean {
    return this.i >= this.text.length;
  }

  private fail(message: string): never {
    throw new StrictParseError(`${message} (offset ${this.i})`);
  }
}
