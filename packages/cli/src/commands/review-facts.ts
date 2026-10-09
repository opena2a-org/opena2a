/**
 * Facts about the reviewed tree that the review report states as evidence
 * instead of inferring: where the env files are, how many values each one
 * assigns, its file mode, and what git does with it.
 *
 * Everything here is read-only and safe to run on a hostile tree:
 * - git runs from an argument array (no shell) with `core.fsmonitor=false`,
 *   because a repository's own config can name an fsmonitor hook that
 *   `git ls-files` would otherwise execute, and with optional locks off, so
 *   the index is never written;
 * - env-file values are counted line by line and never kept;
 * - symlinks are not followed, so nothing outside the tree is read.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { probeEnv } from '../util/child-env.js';
import { SKIP_DIRS, TEMPLATE_ENV_FILES } from '../util/credential-patterns.js';

export interface EnvFileFact {
  /** Path relative to the reviewed directory, `/`-separated. */
  path: string;
  /** Lines that assign a non-empty value. The values are never read into the
   *  report. Null when the file could not be read or is over 1 MB. */
  assignments: number | null;
  /** A git ignore rule matches the file (whether or not it is tracked).
   *  Null when the directory is not inside a git work tree. */
  gitIgnored: boolean | null;
  /** The file is in git's index. Null outside a git work tree. */
  gitTracked: boolean | null;
  /** `git add .` in the reviewed directory covers this file: it is tracked
   *  (ignore rules never apply to tracked files), or it is untracked and no
   *  ignore rule matches it. Null outside a git work tree. */
  stagedByAddAll: boolean | null;
  /** Permission bits as `ls -l` prints them, e.g. `-rw-r--r--`. Null on
   *  Windows, where the mode does not describe who can read the file. */
  mode: string | null;
}

/** How deep below the reviewed directory env files are looked for: the
 *  root, a workspace package and two folders below it. The walk is bounded
 *  so a tree built to be deep cannot make the review recurse without end. */
const MAX_DEPTH = 4;
/** At most this many env files are listed, so a tree planted with thousands
 *  of them cannot grow the report or the git queries without bound. */
const MAX_ENV_FILES = 50;
/** An env file over 1 MiB is not read: its count stays unknown rather than
 *  the review holding a file of that size in memory to count its lines. */
const MAX_ENV_BYTES = 1_048_576;

/** `.env` and `.env.<suffix>`, except the template names that hold placeholders. */
export function isEnvFileName(name: string): boolean {
  return (name === '.env' || name.startsWith('.env.')) && !TEMPLATE_ENV_FILES.has(name);
}

/**
 * Env files under targetDir, in a stable order. Skips the folders the
 * credential scan skips (dependencies, build output, tests) and hidden
 * folders, and does not follow symlinks.
 */
export function findEnvFiles(targetDir: string): string[] {
  const found: string[] = [];
  const walk = (dir: string, rel: string, depth: number): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (found.length >= MAX_ENV_FILES) return;
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isFile() && isEnvFileName(entry.name)) {
        found.push(relPath);
      } else if (entry.isDirectory() && depth < MAX_DEPTH
        && !entry.name.startsWith('.') && !SKIP_DIRS.has(entry.name)) {
        walk(path.join(dir, entry.name), relPath, depth + 1);
      }
    }
  };
  walk(targetDir, '', 0);
  return found;
}

const ASSIGNMENT = /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=(.*)$/;

/** Count `KEY=value` lines with a non-empty value. Values are tested for
 *  emptiness and dropped; nothing is returned but the count. */
export function countAssignments(content: string): number {
  let n = 0;
  for (const line of content.split(/\r?\n/)) {
    const m = ASSIGNMENT.exec(line);
    if (!m) continue;
    const value = m[1].trim();
    if (value === '' || value === '""' || value === "''" || value.startsWith('#')) continue;
    n++;
  }
  return n;
}

/** Permission bits in `ls -l` form for a regular file. */
export function symbolicMode(mode: number): string {
  const letters = 'rwxrwxrwx';
  let out = '-';
  for (let i = 0; i < 9; i++) out += (mode & (0o400 >> i)) ? letters[i] : '-';
  return out;
}

const GIT_SAFE_ARGS = ['--no-optional-locks', '-c', 'core.fsmonitor=false'];

function git(targetDir: string, args: string[], input?: string): string {
  // `-C` reads its next argument as a path even when it starts with a dash;
  // resolving it only makes the path git receives absolute.
  return execFileSync('git', ['-C', path.resolve(targetDir), ...GIT_SAFE_ARGS, ...args], {
    input,
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'ignore'],
    timeout: 10_000,
    // Git needs no credential here. The narrow probe environment also drops
    // GIT_DIR and friends, so a review started from a git hook still asks
    // about the reviewed tree. It keeps XDG_CONFIG_HOME, so git finds the
    // user's global ignore file where it always does.
    env: probeEnv(),
  });
}

export interface GitPathFacts {
  tracked: Set<string>;
  ignored: Set<string>;
}

/**
 * Which of `paths` (relative to targetDir) git tracks, and which an ignore
 * rule matches. Null when targetDir is not inside a git work tree or git
 * cannot answer (not installed, repository owned by another user): the
 * question then has no answer, which is different from "no".
 */
export function gitPathFacts(targetDir: string, paths: string[]): GitPathFacts | null {
  try {
    if (git(targetDir, ['rev-parse', '--is-inside-work-tree']).trim() !== 'true') return null;
    if (paths.length === 0) return { tracked: new Set(), ignored: new Set() };
    // Literal pathspecs: a folder name starting with ':' is a path, not magic.
    // (check-ignore rejects the flag; a path it cannot parse fails the whole
    // query to unknown below.)
    const tracked = new Set(
      git(targetDir, ['--literal-pathspecs', 'ls-files', '-z', '--', ...paths]).split('\0').filter(Boolean),
    );
    let ignoredOut = '';
    try {
      // --no-index: report the rule match itself, so a tracked file that a
      // rule names is visible as "ignored but tracked".
      ignoredOut = git(targetDir, ['check-ignore', '--no-index', '-z', '--stdin'], paths.join('\0') + '\0');
    } catch (err) {
      if ((err as { status?: number | null }).status !== 1) throw err; // 1 means none matched
    }
    return { tracked, ignored: new Set(ignoredOut.split('\0').filter(Boolean)) };
  } catch {
    return null;
  }
}

/** Facts for every env file under targetDir. Never throws. */
export function collectEnvFileFacts(targetDir: string): EnvFileFact[] {
  let files: string[];
  try {
    files = findEnvFiles(targetDir);
  } catch {
    return [];
  }
  if (files.length === 0) return [];
  const gitFacts = gitPathFacts(targetDir, files);
  return files.map((rel) => {
    let assignments: number | null = null;
    let mode: string | null = null;
    try {
      const abs = path.join(targetDir, rel);
      const st = fs.lstatSync(abs);
      if (process.platform !== 'win32') mode = symbolicMode(st.mode);
      if (st.isFile() && st.size <= MAX_ENV_BYTES) assignments = countAssignments(fs.readFileSync(abs, 'utf-8'));
    } catch {
      // Unreadable: the count stays unknown rather than zero.
    }
    const gitTracked = gitFacts ? gitFacts.tracked.has(rel) : null;
    const gitIgnored = gitFacts ? gitFacts.ignored.has(rel) : null;
    return {
      path: rel,
      assignments,
      gitIgnored,
      gitTracked,
      stagedByAddAll: gitFacts ? gitTracked === true || gitIgnored === false : null,
      mode,
    };
  });
}
