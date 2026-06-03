/**
 * Rebrand bundled-tool command citations to their `opena2a`-prefixed form.
 *
 * opena2a-cli bundles hackmyagent / ai-trust / cryptoserve and delegates to
 * them. Those tools (and the Registry data they return) sometimes cite their
 * own binary name in next-step suggestions and usage lines. A user who
 * installed `opena2a` should be told the `opena2a` command, not a bundled
 * binary they may not know exists (issue #190; same intent as HMA_CLI_PREFIX).
 *
 * Only commands with a FAITHFUL `opena2a` equivalent are rewritten. Bundled
 * subcommands opena2a-cli does not expose 1:1 (e.g. `ai-trust audit`) are left
 * unchanged -- suggesting a command that does not resolve would be worse than
 * leaving the original. This function is pure string substitution; it never
 * touches JSON output (callers must skip it in --json mode).
 */

// Order matters: longer / npx-prefixed forms first so they win over the
// shorter bare forms below.
const REBRAND_RULES: ReadonlyArray<readonly [RegExp, string]> = [
  // hackmyagent -- scan adapter exposes both `scan` (primary) and `secure` (alias)
  [/\bnpx hackmyagent secure\b/g, 'opena2a secure'],
  [/\bnpx hackmyagent scan\b/g, 'opena2a scan'],
  [/\bhackmyagent secure\b/g, 'opena2a secure'],
  [/\bhackmyagent scan\b/g, 'opena2a scan'],
  // ai-trust -- registry adapter delegates to `ai-trust check`, so
  // `ai-trust check <pkg>` maps faithfully to `opena2a registry <pkg>`.
  // The `(?![\w-])` guard avoids rewriting a hyphenated subcommand we do not
  // expose (e.g. a future `ai-trust check-deps` must NOT become a nonexistent
  // `opena2a registry-deps`); leave such tokens untouched rather than break them.
  [/\bnpx ai-trust check(?![\w-])/g, 'opena2a registry'],
  [/\bai-trust check(?![\w-])/g, 'opena2a registry'],
  // cryptoserve -- crypto adapter
  [/\bnpx cryptoserve\b/g, 'opena2a crypto'],
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
