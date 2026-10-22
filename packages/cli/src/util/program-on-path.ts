/**
 * Looking a program up on PATH without searching an empty or relative entry.
 *
 * An entry of PATH that is not an absolute directory — `.`, a bare `bin`,
 * `node_modules/.bin`, or the empty entry a leading, trailing or doubled
 * separator leaves — is resolved by the OS against the process's working
 * directory. For a scanner that runs in a directory it was handed (a cloned
 * repository, an unpacked archive), that directory is attacker-controlled, so
 * a program placed there could answer as the CLI being looked up, or as an
 * interpreter a found CLI then starts on the same PATH.
 *
 * `npmOnPath` in commands/detect.ts applies this same rule to `npm`; this is
 * the shared form so every probe can reach it.
 */
import { accessSync, constants, statSync } from 'node:fs';
import { delimiter, isAbsolute, join } from 'node:path';

/**
 * The absolute path of the first executable regular file named `name` in an
 * absolute directory of `env.PATH`, or null when no absolute directory holds
 * one. Every empty or relative PATH entry is skipped, so the answer is always
 * a path an absolute PATH directory names.
 */
export function programOnPath(name: string, env: NodeJS.ProcessEnv = process.env): string | null {
  for (const dir of (env.PATH ?? '').split(delimiter)) {
    if (!isAbsolute(dir)) continue;
    const candidate = join(dir, name);
    try {
      accessSync(candidate, constants.X_OK);
      if (statSync(candidate).isFile()) return candidate;
    } catch {
      // Not an executable regular file in this directory; try the next.
    }
  }
  return null;
}

/**
 * The absolute directories of `env.PATH`, in order, rebuilt into a PATH
 * string. Used as the PATH of the environment a probed program runs in, so the
 * program's own lookups cannot reach a relative entry either. Empty and
 * relative entries are dropped.
 */
export function absolutePathDirs(env: NodeJS.ProcessEnv = process.env): string {
  return (env.PATH ?? '')
    .split(delimiter)
    .filter((dir) => isAbsolute(dir))
    .join(delimiter);
}
