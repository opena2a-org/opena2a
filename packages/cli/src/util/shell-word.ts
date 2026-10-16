import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Render a scanned path as one POSIX shell word, for a command the CLI prints
 * for the user to paste (a Fix, a Verify, a recommendation).
 *
 * The path is a file name the scanned repository chose, so it is untrusted.
 * Inside single quotes sh, bash and zsh expand nothing: `$(...)`, backticks,
 * `;`, spaces and globs stay literal. An embedded `'` is written as `'\''`.
 * A path that begins with `-` gets `./` so the receiving command (`git`,
 * `head`, `sed`) cannot read it as an option. Every path takes this one form,
 * plain names included, so there is no classifier to get wrong.
 */
export function shellWord(p: string): string {
  const word = p.startsWith('-') ? `./${p}` : p;
  return `'${word.replace(/'/g, `'\\''`)}'`;
}

/**
 * The path that names `file` from `cwd`, the directory the command was run
 * in and where the user pastes what it prints: relative to `cwd` when the
 * file is under it (`.` for `cwd` itself), absolute otherwise. A path
 * relative to any other directory, the scanned one for instance, does not
 * resolve there. Two spellings of one directory (macOS `/var` and
 * `/private/var`) are compared by their real paths; the file's own name is
 * kept, so a symlink is named, not its target.
 */
export function pathFrom(file: string, cwd: string = process.cwd()): string {
  const abs = path.resolve(cwd, file);
  const real = path.join(realpathOr(path.dirname(abs)), path.basename(abs));
  return relativeUnder(cwd, abs) ?? relativeUnder(realpathOr(cwd), real) ?? abs;
}

/** `pathFrom` as one shell word: the form every printed command takes. */
export function shellPath(file: string, cwd: string = process.cwd()): string {
  return shellWord(pathFrom(file, cwd));
}

function relativeUnder(dir: string, file: string): string | null {
  const rel = path.relative(dir, file);
  if (rel === '') return '.';
  if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) return null;
  return rel;
}

function realpathOr(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
}
