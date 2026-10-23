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
 *
 * A program found here is started by the absolute path returned, with a PATH
 * of only absolute directories (`withAbsolutePathDirs`, `absolutePathDirs`),
 * in a working directory made for the run (`withEmptyWorkDir`), so neither the
 * lookup nor anything the program looks up in turn is resolved against the
 * directory the CLI was started in.
 */
import { accessSync, constants, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
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

/**
 * A copy of `env` whose PATH is `absolutePathDirs(env)`. The source a child
 * environment resolver (`probeEnv`) filters for a program started by its
 * absolute path, so the started program's own lookups skip empty and
 * relative entries too.
 */
export function withAbsolutePathDirs(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return Object.assign({}, env, { PATH: absolutePathDirs(env) });
}

/** The working directory of one run: made for it, or the reason there is none. */
export type EmptyWorkDir =
  | { path: string; reason: null }
  | { path: null; reason: string };

/**
 * Run `fn` with a working directory made for this run alone: a new, empty
 * directory created with `mkdtemp` under the system temporary directory, and
 * removed when `fn` returns or throws. It is never HOME and never the
 * directory the CLI was started in, whatever HOME holds.
 *
 * When the temporary directory is not an absolute path (a relative one would
 * be created under the directory the CLI was started in) or the directory
 * cannot be made, `fn` gets `path: null` with the reason, and must start
 * nothing: there is no fallback directory.
 */
export function withEmptyWorkDir<T>(prefix: string, fn: (workDir: EmptyWorkDir) => T): T {
  let made: string | null = null;
  let workDir: EmptyWorkDir;
  try {
    const base = tmpdir();
    if (!isAbsolute(base)) {
      throw new Error(`the temporary directory "${base}" is not an absolute path`);
    }
    made = mkdtempSync(join(base, prefix));
    workDir = { path: made, reason: null };
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    workDir = { path: null, reason: `no empty working directory could be made: ${detail}` };
  }
  try {
    return fn(workDir);
  } finally {
    if (made !== null) {
      try {
        rmSync(made, { recursive: true, force: true });
      } catch {
        // Best effort: what is left is a directory under the temporary directory.
      }
    }
  }
}
