/**
 * Every `opena2a <verb>` the bundled scanner can print is a command this CLI
 * registers.
 *
 * hackmyagent cites its own verbs under the wrapper's prefix
 * (HMA_CLI_PREFIX=opena2a, set in src/index.ts), so each
 * `${CLI_PREFIX} <verb>` in its CLI reaches the user as `opena2a <verb>`.
 * `opena2a-cli` installs one bin, so a cited verb opena2a does not register is
 * a dead end: `check --nanomind` printed "Run: opena2a nanomind setup" and the
 * command answered `unknown command 'nanomind'`.
 *
 * The verbs are read from the engine this package resolves, so a hackmyagent
 * upgrade that starts citing a new verb fails here until the verb is
 * registered or listed below.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';

import { ADAPTER_REGISTRY } from '../src/adapters/registry.js';
import { knownCommandNames } from '../src/natural/known-commands.js';

const CLI_ROOT = resolve(__dirname, '..');

// Resolved the way the CLI resolves it: from this package, not from the cwd.
const fromCli = createRequire(join(CLI_ROOT, 'package.json'));
const ENGINE_CLI = join(dirname(fromCli.resolve('hackmyagent')), 'cli.js');

/**
 * Verbs the pinned engine cites that opena2a does not register yet, with
 * where the engine cites them. Each is an open dead end, not an accepted one:
 * listed so the gap is a visible diff rather than a silent skip. Registering
 * a verb, or an engine release that stops citing it, fails the last test
 * below until its entry is removed.
 */
const KNOWN_UNREGISTERED: Readonly<Record<string, string>> = {
  attack: 'root help, attack help and report, wild report, check <package> next steps',
  'check-metadata': 'explain output',
  explain: 'scan-soul output',
  'init-mcp': 'init-mcp help',
  'pull-stubs': 'pull-stubs help and its own usage error',
  'red-team': 'red-team output',
  'secure-nemoclaw': 'secure-nemoclaw help (hidden, deprecated command)',
  'secure-openclaw': 'secure-openclaw help, secure-nemoclaw output',
  wild: 'wild help',
};

/** The verb after every `${CLI_PREFIX} ` in the engine's CLI. */
function citedVerbs(): Set<string> {
  const src = readFileSync(ENGINE_CLI, 'utf-8');
  return new Set([...src.matchAll(/CLI_PREFIX\}\s+([a-z][a-z0-9-]*)/g)].map((m) => m[1]));
}

/** Top-level command names and adapter aliases the program registers. */
function registeredVerbs(): Set<string> {
  const verbs = new Set(knownCommandNames());
  for (const config of Object.values(ADAPTER_REGISTRY)) {
    for (const alias of config.aliases ?? []) verbs.add(alias);
  }
  return verbs;
}

describe('verbs the bundled scanner cites under the opena2a prefix', () => {
  const cited = citedVerbs();
  const registered = registeredVerbs();

  it('reads citations from the engine', () => {
    // If the pattern stops matching, the checks below pass vacuously.
    expect(cited).toContain('secure');
    expect(cited).toContain('nanomind');
  });

  it('every cited verb is a registered opena2a command', () => {
    const unregistered = [...cited]
      .filter((v) => !registered.has(v) && !(v in KNOWN_UNREGISTERED))
      .sort();
    expect(unregistered, `cited by hackmyagent but not registered: ${unregistered.join(', ')}`).toEqual([]);
  });

  it('every known-unregistered entry is still cited and still unregistered', () => {
    const stale = Object.keys(KNOWN_UNREGISTERED)
      .filter((v) => !cited.has(v) || registered.has(v))
      .sort();
    expect(stale, `remove from KNOWN_UNREGISTERED: ${stale.join(', ')}`).toEqual([]);
  });
});
