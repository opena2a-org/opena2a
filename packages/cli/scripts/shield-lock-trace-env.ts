/**
 * The environment shield-lock-trace-loop.ts hands each vitest run (#397).
 *
 * The run is this repository's own vitest on the concurrent-write suite, and
 * the suite's tsx writers inherit the worker's environment. None of them
 * reads a credential, so none is passed. The child gets the base allowlist
 * every child gets (PATH, HOME, TMPDIR, locale, terminal and CI hints, proxy
 * and CA settings, OPENA2A_*), the Node toolchain's own settings, the suite's
 * writer count, the round count and the trace path. A variable this list did
 * not anticipate goes through OPENA2A_CHILD_ENV_ALLOW, which says so.
 */
import { buildChildEnv } from '../src/util/child-env.js';
import { LOCK_TRACE_ENV } from '../src/shield/lock.js';

/** Node, npm and version-manager settings vitest and tsx may depend on. */
const NODE_PREFIXES = ['npm_config_', 'NPM_CONFIG_', 'NODE_', 'NVM_', 'COREPACK_'];

/**
 * @param traceFile this round's trace file, set as the lock trace target.
 * @param source    environment to draw from. Defaults to `process.env`.
 * @param onNotice  told when OPENA2A_CHILD_ENV_ALLOW widens or is refused.
 */
export function lockTraceSuiteEnv(
  traceFile: string,
  source: NodeJS.ProcessEnv = process.env,
  onNotice?: (message: string) => void,
): NodeJS.ProcessEnv {
  return buildChildEnv(
    {
      allow: ['SHIELD_CONCURRENT_WRITERS'],
      allowPrefixes: NODE_PREFIXES,
      set: {
        [LOCK_TRACE_ENV]: traceFile,
        SHIELD_CONCURRENT_ROUNDS: source.SHIELD_CONCURRENT_ROUNDS ?? '1',
      },
    },
    source,
    onNotice,
  );
}
