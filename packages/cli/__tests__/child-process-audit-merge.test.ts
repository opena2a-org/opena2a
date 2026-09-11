/**
 * Why the audited set is the table and never a sentence (QGF-146.AC4).
 *
 * The property is textual locality, and `git merge-tree --write-tree` is the
 * instrument that decides it. Adding a row to CHILD_PROCESS_AUDIT is a local
 * edit: two deliveries that each add their own row touch no line in common,
 * and git merges them without help. A count in the docstring is not local:
 * every delivery that changes the set has to rewrite the same sentence, so
 * two of them rewrite it differently and collide — which is exactly what
 * opena2a #339 (FIVE -> six) and #340 (FIVE -> SEVEN) did to each other, both
 * ways, on this file.
 *
 * So this cell rebuilds both merges offline over throwaway repositories: the
 * delivered file merges clean, the same file carrying the old count sentence
 * conflicts, and the control in between shows the conflict comes from the
 * sentence rather than from the two rows.
 */
import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/** The delivered file, read from the tree — never a fixture copy of it. */
const AUDIT_IN_TREE = path.join(__dirname, 'child-process-audit.ts');

/** Its path in this repository, so git reports the path the queue collided on. */
const AUDIT_PATH = path
  // __tests__ -> cli -> packages -> the repository root.
  .relative(path.resolve(__dirname, '..', '..', '..'), AUDIT_IN_TREE)
  .split(path.sep)
  .join('/');

/**
 * The count comment this delivery removed, quoted from child-process-audit.ts
 * at d467dc2a5a062a53b91ab4009147a20577df71c2. Both of its numbers were
 * already wrong against that tree. It is here as the fixture the collision is
 * rebuilt from and describes nothing about this one: the audited set is
 * written down once, by the table in child-process-audit.ts.
 */
const COUNT_COMMENT = [
  ` * Measured population, correcting the roadmap unit's "other six": besides`,
  ' * shield/concurrent-write.test.ts there are FIVE real spawners, all',
  ' * synchronous and one child at a time. Four more files only',
  " * `vi.mock('node:child_process', ...)` and spawn nothing real —",
  ' * shield/llm.test.ts and shield/llm-backend.test.ts (the two the unit',
  ' * counted), plus adapters/docker.test.ts and',
  ' * adapters/child-env-wiring.test.ts; none has the static import, so the',
  ' * enumeration below correctly excludes them.',
  ' *',
  '',
].join('\n');

/** Where that paragraph sat, and the sentence each side rewrote. */
const COMMENT_ANCHOR = ' * Root `package.json` keeps';
const COUNT_SENTENCE = 'there are FIVE real spawners';

const OPENS_TABLE = 'export const CHILD_PROCESS_AUDIT: Record<string, ChildProcessAuditEntry> = {\n';
const CLOSES_TABLE = '\n};\n';

/** A new spawning test file's audit entry, in the shape the table uses. */
function entry(key: string): string {
  return (
    `  '${key}': {\n` +
    `    shape: 'sync',\n` +
    `    maxSimultaneousChildren: 1,\n` +
    `    spawns: 'execFileSync(git ...) fixture setup',\n` +
    '  },\n'
  );
}

/** One new entry at the top of the table, and nothing else. */
function addEntryFirst(source: string, key: string): string {
  const opens = source.indexOf(OPENS_TABLE);
  if (opens === -1) throw new Error(`${AUDIT_PATH} does not open the table where expected`);
  const at = opens + OPENS_TABLE.length;
  return source.slice(0, at) + entry(key) + source.slice(at);
}

/** One new entry at the bottom of the table, and nothing else. */
function addEntryLast(source: string, key: string): string {
  const closes = source.lastIndexOf(CLOSES_TABLE);
  if (closes === -1) throw new Error(`${AUDIT_PATH} does not close the table where expected`);
  const at = closes + 1;
  return source.slice(0, at) + entry(key) + source.slice(at);
}

/** The file as it was before this delivery: the count paragraph put back. */
function withCountComment(source: string): string {
  const at = source.indexOf(COMMENT_ANCHOR);
  if (at === -1) throw new Error(`${AUDIT_PATH} lost the paragraph the count sentence sat above`);
  return source.slice(0, at) + COUNT_COMMENT + source.slice(at);
}

/** What a delivery had to do to that sentence to keep it true. */
function rewriteCount(source: string, to: string): string {
  if (!source.includes(COUNT_SENTENCE)) throw new Error('no count sentence to rewrite');
  return source.replace(COUNT_SENTENCE, `there are ${to} real spawners`);
}

describe('child-process audit: a row merges, a count sentence does not', () => {
  const repoDirs: string[] = [];
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    // Hermetic: a developer's own git config cannot supply a merge driver, a
    // conflict style or an attributes file that flips these results.
    for (const key of ['GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM']) {
      savedEnv[key] = process.env[key];
      process.env[key] = '/dev/null';
    }
  });

  afterEach(() => {
    while (repoDirs.length > 0) {
      fs.rmSync(repoDirs.pop()!, { recursive: true, force: true });
    }
    for (const [key, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  /**
   * A throwaway repository holding the audit file at its real path: a base
   * commit, then one branch per delivery, each branched off that base.
   */
  function scratchRepo(base: string, branches: Record<string, string>): string {
    const repoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-audit-merge-'));
    repoDirs.push(repoDir);
    const git = (...args: string[]) =>
      execFileSync(
        'git',
        ['-C', repoDir, '-c', 'user.email=test@example.com', '-c', 'user.name=Test', ...args],
        { stdio: 'pipe' },
      ).toString();
    const commit = (source: string, message: string) => {
      fs.mkdirSync(path.join(repoDir, path.dirname(AUDIT_PATH)), { recursive: true });
      fs.writeFileSync(path.join(repoDir, AUDIT_PATH), source);
      git('add', AUDIT_PATH);
      git('commit', '-q', '-m', message);
    };

    git('init', '-q');
    commit(base, 'base');
    const baseCommit = git('rev-parse', 'HEAD').trim();
    for (const [branch, source] of Object.entries(branches)) {
      git('checkout', '-q', '-b', branch, baseCommit);
      commit(source, branch);
    }
    return repoDir;
  }

  /** The paths `git merge-tree --write-tree` reports as conflicted. */
  function conflicts(repoDir: string, ours: string, theirs: string): string[] {
    let stdout: string;
    try {
      stdout = execFileSync(
        'git',
        ['-C', repoDir, 'merge-tree', '--write-tree', '--name-only', ours, theirs],
        { stdio: 'pipe' },
      ).toString();
      return []; // exit 0: merged clean, and the tree it wrote is the only output
    } catch (failure) {
      const { status, stdout: out, stderr } = failure as {
        status?: number;
        stdout?: Buffer;
        stderr?: Buffer;
      };
      if (status !== 1) throw new Error(`git merge-tree exit ${status}: ${String(stderr ?? '')}`);
      // exit 1: <tree oid>, then the conflicted paths, then a blank line and
      // git's own messages about them.
      stdout = String(out ?? '');
    }
    const [, ...rest] = stdout.split('\n');
    const blank = rest.indexOf('');
    return blank === -1 ? rest : rest.slice(0, blank);
  }

  /** Merging is symmetric here, so both orders are asked. */
  function conflictsBothWays(repoDir: string, a: string, b: string): string[][] {
    return [conflicts(repoDir, a, b), conflicts(repoDir, b, a)];
  }

  it('QGF-146.AC4 two deliveries each add their own row and merge clean; the same two rewriting one count sentence conflict', () => {
    const delivered = fs.readFileSync(AUDIT_IN_TREE, 'utf-8');

    // Each branch adds exactly one entry, for a distinct new spawning test
    // file, at a distinct position in the table, and changes nothing else.
    const early = (source: string) => addEntryFirst(source, 'commands/rollout-smoke.test.ts');
    const late = (source: string) => addEntryLast(source, 'shield/quarantine-spawn.test.ts');

    const clean = scratchRepo(delivered, {
      'add-early': early(delivered),
      'add-late': late(delivered),
    });
    for (const conflicted of conflictsBothWays(clean, 'add-early', 'add-late')) {
      expect(
        conflicted,
        'two rows added at distinct positions of the delivered table must merge without a ' +
          'conflict, in either direction: that is the whole reason the set is a table',
      ).toEqual([]);
    }

    // The control: the same two rows over a base that still carries the count
    // paragraph, with neither side touching it. Still clean — so a conflict
    // below comes from the sentence, not from the paragraph being there.
    const untouched = withCountComment(delivered);
    const control = scratchRepo(untouched, {
      'add-early': early(untouched),
      'add-late': late(untouched),
    });
    for (const conflicted of conflictsBothWays(control, 'add-early', 'add-late')) {
      expect(conflicted, 'the count paragraph alone conflicts with nothing').toEqual([]);
    }

    // The collision the merge queue recorded: each side additionally corrects
    // the count sentence to the number its own delivery made true.
    const queued = scratchRepo(untouched, {
      'pr-339': rewriteCount(early(untouched), 'six'),
      'pr-340': rewriteCount(late(untouched), 'SEVEN'),
    });
    for (const conflicted of conflictsBothWays(queued, 'pr-339', 'pr-340')) {
      expect(
        conflicted,
        'each delivery had to restate the whole set in one shared sentence, so the two ' +
          'rewrites collide on it in both directions — the defect this contract removes',
      ).toEqual([AUDIT_PATH]);
    }
  });
});
