import { ADAPTER_REGISTRY } from '../adapters/registry.js';

/**
 * Core (non-adapter) command names registered on the Commander program.
 * Kept here as the single source of truth so both the natural-language
 * dispatch fallback in `index.ts` and the help/NL-example regression test
 * read the same list.
 *
 * A multi-word phrase whose first token is in this set (or an adapter name)
 * is an explicit command invocation and must reach Commander directly --
 * it is NOT treated as natural language. Conversely, any natural-language
 * example shown in `--help` MUST have a first token OUTSIDE this set, or it
 * silently routes to the command instead of the NL matcher (the
 * `opena2a detect credentials` help collision fixed in 0.10.6).
 */
export const CORE_COMMAND_NAMES: readonly string[] = [
  'init', 'protect', 'comply', 'guard', 'runtime', 'shield', 'review', 'identity',
  'config', 'self-register', 'verify', 'baselines', 'benchmark',
  'check', 'status', 'publish', 'detect', 'mcp', 'demo', 'setup', 'watch',
  'trust', 'claim', 'create', 'login', 'logout', 'whoami', 'admin',
  // Registered on the program but missing here until #291, which let
  // `opena2a skill create a b` reach the NL matcher before Commander.
  // __tests__/natural/known-commands.test.ts now fails on any drift.
  'skill', 'harden-skill', 'harden-soul', 'scan-soul', 'telemetry',
];

/** Every command name Commander will route directly: adapters + core. */
export function knownCommandNames(): string[] {
  return [...Object.keys(ADAPTER_REGISTRY), ...CORE_COMMAND_NAMES];
}

/** True when `name` is a registered command (and thus not free-form text). */
export function isKnownCommand(name: string): boolean {
  return knownCommandNames().includes(name);
}

// A compound verb (`fix-all`, `scan-souls`): hyphenated lowercase words.
// Natural-language phrases start with an ordinary word.
const COMPOUND_VERB = /^[a-z0-9]+(?:-[a-z0-9]+)+$/i;

/**
 * True when argv reads as an explicit command invocation rather than an
 * unquoted natural-language phrase: a flag after the first token, or a first
 * token shaped like a compound subcommand. Such input must reach Commander,
 * which reports the unknown verb and exits non-zero. Before #291 the NL
 * matcher answered for it: `opena2a fix-all --with-aim` printed "Matched:
 * opena2a identity" and exited 0, so a user and any CI consumer saw success
 * for a command that does not exist. The quoted form (`opena2a "..."`) stays
 * the way to ask a question that contains a flag-like word.
 */
export function looksLikeCommandInvocation(args: readonly string[]): boolean {
  if (args.length === 0) return false;
  if (COMPOUND_VERB.test(args[0])) return true;
  return args.slice(1).some(a => a.startsWith('-'));
}

/**
 * Whether the unquoted multi-word NL fallback in `index.ts` may try `args`:
 * two or more tokens, the first neither a flag nor a registered command, and
 * the whole not shaped like a command invocation.
 */
export function shouldTryNaturalLanguageFallback(args: readonly string[]): boolean {
  if (args.length < 2) return false;
  if (args[0].startsWith('-')) return false;
  if (isKnownCommand(args[0])) return false;
  return !looksLikeCommandInvocation(args);
}
