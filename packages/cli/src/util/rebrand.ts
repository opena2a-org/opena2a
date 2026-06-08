/**
 * Rebrand bundled-tool command citations to their `opena2a`-prefixed form.
 *
 * opena2a-cli bundles hackmyagent / secretless-ai / ai-trust / cryptoserve and
 * delegates to them. Those tools (and the Registry data they return) cite their
 * own binary name in usage lines, help text, and next-step suggestions. A user
 * who installed `opena2a` should be told the `opena2a` command, not a bundled
 * binary they may not know exists (issues #190, #191; same intent as the
 * HMA_CLI_PREFIX / *_CLI_PREFIX env vars exported in index.ts).
 *
 * DESIGN — verb-anchored, never bare program names. Each rule rewrites a
 * `<tool> <verb>` PAIR where `<verb>` is one the matching `opena2a` command
 * forwards faithfully (the adapter passes the verb straight through, so
 * `opena2a crypto login` really runs `cryptoserve login`). We deliberately do
 * NOT rewrite a bare tool token, because the tool's package name legitimately
 * appears in contexts that are NOT command citations and must survive intact:
 *   - Python:  `from cryptoserve import CryptoServe`  (cryptoserve's own help)
 *   - JS:      `import { x } from 'secretless-ai'`
 *   - install: `npm install secretless-ai`, `pip install cryptoserve`
 * Anchoring on the verb set means `cryptoserve import` / `secretless-ai'` /
 * a trailing `cryptoserve\n` never match. Only commands with a FAITHFUL
 * `opena2a` equivalent are rewritten; bundled subcommands opena2a-cli does not
 * expose 1:1 (e.g. `ai-trust audit`) are left unchanged -- suggesting a command
 * that does not resolve would be worse than leaving the original.
 *
 * This function is pure string substitution; it never touches JSON output
 * (callers must skip it in --json / --format json|sarif mode).
 */

/**
 * hackmyagent verbs opena2a forwards faithfully. CONSERVATIVE on purpose: the
 * `scan` adapter exposes `scan`/`secure`, and the router routes `check <pkg>`
 * to HMA. Other HMA verbs (harden-soul, trust, detect, ...) have opena2a
 * commands whose semantics may differ, so we do not claim them.
 */
const HMA_VERBS = ['secure', 'scan', 'check'] as const;

/**
 * secretless-ai verbs. The `secrets` adapter forwards args verbatim (no
 * subcommand), so EVERY secretless-ai verb maps faithfully to
 * `opena2a secrets <verb>`. (`broker` is also reachable as `opena2a broker`,
 * but `opena2a secrets broker` works too, so the generic mapping is safe.)
 */
const SECRETLESS_VERBS = [
  'backend', 'broker', 'cache', 'clean-history', 'clean', 'doctor', 'engine',
  'env', 'hook', 'import', 'install', 'mcp-status', 'mcp-unprotect', 'migrate',
  'protect-mcp', 'rules', 'run', 'scan-history', 'scan', 'scope', 'secret',
  'setup', 'status', 'verify', 'warm', 'watch', 'init',
] as const;

/**
 * cryptoserve verbs. The `crypto` python adapter forwards args verbatim, so
 * every cryptoserve verb maps faithfully to `opena2a crypto <verb>`. `help` is
 * excluded (too common a bare word; `opena2a crypto --help` is the real form).
 */
const CRYPTOSERVE_VERBS = [
  'hash-password', 'backups', 'backup', 'cbom', 'certs', 'contexts', 'decrypt',
  'deps', 'encrypt', 'gate', 'info', 'login', 'logout', 'pqc', 'promote',
  'push', 'restore', 'scan', 'status', 'token', 'verify', 'wizard',
] as const;

/**
 * Build a `(?:npx )?<tool> (<verb>|...)` rule whose replacement is
 * `<prefix> $1`. Verbs are sorted longest-first so a real hyphenated verb
 * (`scan-history`) wins over its prefix (`scan`). The optional `npx ` is
 * consumed so the rewritten form never carries it.
 *
 * Two anchors keep this from corrupting non-citations:
 *   - Left: `(?<![\w@/.-])` instead of a bare `\b`, so an EMBEDDING prefix does
 *     not leak through. `\b` matches inside `my-secretless-ai` / `@org/cryptoserve`
 *     / `tools/cryptoserve` (the boundary sits at the `-` or `/`), which would
 *     rewrite a scoped/forked package name or a path. The lookbehind requires
 *     the tool token to start at a true word/path boundary.
 *   - Right: `(?![\w-])` after the verb, so a real-but-unmapped hyphenated
 *     subcommand is left intact rather than half-rewritten. Without it,
 *     `hackmyagent check-metadata` (a real HMA verb opena2a does NOT expose)
 *     becomes the nonexistent `opena2a check-metadata`. Same discipline as the
 *     ai-trust `check(?![\w-])` rule below.
 */
function buildVerbRule(
  tool: string,
  verbs: readonly string[],
  prefix: string,
): readonly [RegExp, string] {
  const escaped = tool.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const alt = [...verbs].sort((a, b) => b.length - a.length).join('|');
  return [new RegExp(`(?:npx )?(?<![\\w@/.-])${escaped}\\s+(${alt})(?![\\w-])`, 'g'), `${prefix} $1`];
}

// Order: verb-pair rules first, then the bare-program Usage line for tools
// whose usage placeholder (`<command>`) is not a real verb the rules catch.
const REBRAND_RULES: ReadonlyArray<readonly [RegExp, string]> = [
  buildVerbRule('hackmyagent', HMA_VERBS, 'opena2a'),
  buildVerbRule('secretless-ai', SECRETLESS_VERBS, 'opena2a secrets'),
  buildVerbRule('cryptoserve', CRYPTOSERVE_VERBS, 'opena2a crypto'),
  // ai-trust -- registry adapter delegates to `ai-trust check`, so
  // `ai-trust check <pkg>` maps faithfully to `opena2a registry <pkg>`.
  // The `(?![\w-])` guard avoids rewriting a hyphenated subcommand we do not
  // expose (e.g. a future `ai-trust check-deps` must NOT become a nonexistent
  // `opena2a registry-deps`); leave such tokens untouched rather than break them.
  [/(?:npx )?(?<![\w@/.-])ai-trust check(?![\w-])/g, 'opena2a registry'],
  // cryptoserve's usage line cites the bare program with a `<command>`
  // placeholder (not a real verb), so the verb rule above does not catch it.
  // `Usage: cryptoserve <command>` -> `Usage: opena2a crypto <command>`.
  [/\bUsage:(\s+)cryptoserve\b/g, 'Usage:$1opena2a crypto'],
];

/** Rewrite faithful bundled-tool command citations in a string to opena2a form. */
export function rebrandBundledCommands(text: string): string {
  let out = text;
  for (const [pattern, replacement] of REBRAND_RULES) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

/**
 * Line-buffered transform usable on a streaming child-process stdout. Returns a
 * function that accepts raw chunks and emits rebranded chunks, buffering any
 * trailing partial segment until the next chunk (or flush). This preserves live
 * streaming (we do not wait for the whole output) while only ever rewriting
 * complete segments, so a bundled-tool token split across a chunk boundary is
 * still rewritten correctly.
 *
 * Segments are delimited by `\n` OR `\r`, so carriage-return progress UIs
 * (e.g. a spinner that rewrites one line with `\r`) still stream live rather
 * than being withheld until flush.
 */
export function createLineRebrander(): { push: (chunk: string) => string; flush: () => string } {
  let pending = '';
  return {
    push(chunk: string): string {
      pending += chunk;
      const boundary = Math.max(pending.lastIndexOf('\n'), pending.lastIndexOf('\r'));
      if (boundary === -1) return '';
      const complete = pending.slice(0, boundary + 1);
      pending = pending.slice(boundary + 1);
      return rebrandBundledCommands(complete);
    },
    flush(): string {
      if (!pending) return '';
      const out = rebrandBundledCommands(pending);
      pending = '';
      return out;
    },
  };
}
