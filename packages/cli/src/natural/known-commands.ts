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
  'init', 'protect', 'guard', 'runtime', 'shield', 'review', 'identity',
  'config', 'self-register', 'verify', 'baselines', 'benchmark',
  'check', 'status', 'publish', 'detect', 'mcp', 'demo', 'setup', 'watch',
  'trust', 'claim', 'create', 'login', 'logout', 'whoami',
];

/** Every command name Commander will route directly: adapters + core. */
export function knownCommandNames(): string[] {
  return [...Object.keys(ADAPTER_REGISTRY), ...CORE_COMMAND_NAMES];
}

/** True when `name` is a registered command (and thus not free-form text). */
export function isKnownCommand(name: string): boolean {
  return knownCommandNames().includes(name);
}
