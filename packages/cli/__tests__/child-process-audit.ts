/**
 * Audit of every packages/cli test file that spawns child processes
 * (QGF-40.AC5): each file under __tests__ with a static
 * `import ... from 'node:child_process'`, its spawn shape and the maximum
 * number of children it holds live at once. The test beside this file
 * enumerates those imports from the tree and fails when a file that imports
 * the module is missing here (or listed here without the import), so this
 * table cannot silently go stale.
 *
 * The audited population is the table below and is written down nowhere
 * else. A test file that gains the static import becomes a new entry here,
 * a file that loses it drops out, and either way the edit is local: a
 * delivery adds its own row and rewrites no line another delivery needs.
 * Files that merely `vi.mock('node:child_process', ...)` spawn nothing real
 * and carry no static import, so the enumeration excludes them.
 *
 * A prose tally of the same set used to sit here, and it was wrong on main
 * without a single assertion turning red — nothing reads a docstring. Worse,
 * keeping it right meant every delivery that changed the set had to rewrite
 * the same sentence, so deliveries that landed together collided on it
 * (opena2a #339 and #340) while their table rows merged cleanly.
 * child-process-audit.test.ts now fails if a count comes back into this
 * comment, and child-process-audit-merge.test.ts pins the difference in
 * merge behaviour that is the reason for keeping it out (QGF-146).
 *
 * Root `package.json` keeps `turbo run test --concurrency=1` (QGF-40.AC4
 * retention record): every vitest instance carries the fixed
 * BASE_TASKS = 172 cost (main process plus a 16-process esbuild service
 * pool — see ../vitest.workers.ts) and derives its worker cap assuming it
 * owns the whole cgroup budget. Two package suites at once would hold
 * 2 x 172 = 344 fixed tasks of the 512 cap before any worker, while each
 * instance still derived maxWorkers = 2 (claiming 2 x 95 more apiece,
 * 2 x (172 + 190) = 724 total) — over the cap even though each instance is
 * individually within it. Raise the turbo concurrency only alongside a
 * derivation that accounts for concurrent instances.
 */

export interface ChildProcessAuditEntry {
  /** 'sync' blocks on one child; 'async-bounded' fans out under a ceiling. */
  shape: 'sync' | 'async-bounded';
  /** Peak child processes the file holds live at once (direct children). */
  maxSimultaneousChildren: number;
  /** What the file spawns. */
  spawns: string;
}

/** Keyed by path relative to packages/cli/__tests__/. */
export const CHILD_PROCESS_AUDIT: Record<string, ChildProcessAuditEntry> = {
  'shield/concurrent-write.test.ts': {
    shape: 'async-bounded',
    maxSimultaneousChildren: 4,
    spawns:
      'spawn(tsx concurrent-write-child.ts) — MAX_LIVE_CHILDREN = 4 tsx children ' +
      'live at once (each running the CLI in its own node child, so 8 processes ' +
      'worst case); was an unbounded N=8 Promise.all fan-out before QGF-40',
  },
  'version-stream-split.test.ts': {
    shape: 'sync',
    maxSimultaneousChildren: 1,
    spawns: 'spawnSync(node dist/index.js --version/--help)',
  },
  'commands/guard.test.ts': {
    shape: 'sync',
    maxSimultaneousChildren: 1,
    spawns: 'execFileSync(git ...) fixture setup',
  },
  'commands/init-verify-command.test.ts': {
    shape: 'sync',
    maxSimultaneousChildren: 1,
    spawns: 'execSync(cmd, { shell: /bin/sh })',
  },
  'commands/protect-noninteractive-and-rollback.test.ts': {
    shape: 'sync',
    maxSimultaneousChildren: 1,
    spawns: 'execFileSync(git ...) fixture setup',
  },
  'docs/ci-cd-recipe-jq-paths.test.ts': {
    shape: 'sync',
    maxSimultaneousChildren: 1,
    spawns: 'spawnSync(jq | bash | node) recipe probes',
  },
  'release-first-party-pins.test.ts': {
    shape: 'sync',
    maxSimultaneousChildren: 1,
    spawns:
      'spawnSync(node scripts/check-first-party-pins.mjs) once per case; two of ' +
      'those cases put an `npm` stub on PATH, which the script then runs as a ' +
      'grandchild, still one at a time (QGF-145)',
  },
  'shield/claude-env-contract.test.ts': {
    shape: 'sync',
    maxSimultaneousChildren: 1,
    spawns:
      'spawnSync(probe) once to find an executable scratch dir; then the module ' +
      'under test runs execFileSync(which | claude) against stubs on PATH (#246)',
  },
  'child-process-audit-merge.test.ts': {
    shape: 'sync',
    maxSimultaneousChildren: 1,
    spawns:
      'execFileSync(git init | add | commit | checkout | merge-tree) over throwaway ' +
      'repositories built from this file (QGF-146.AC4)',
  },
};
