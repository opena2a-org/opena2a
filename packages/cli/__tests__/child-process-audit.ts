/**
 * Audit of every packages/cli test file that spawns child processes
 * (QGF-40.AC5): each file under __tests__ with a static
 * `import ... from 'node:child_process'`, its spawn shape and the maximum
 * number of children it holds live at once. child-process-audit.test.ts
 * enumerates those imports from the tree and fails when an importing file is
 * missing here (or listed here without importing), so this table cannot
 * silently go stale.
 *
 * Measured population, correcting the roadmap unit's "other six": besides
 * shield/concurrent-write.test.ts there are FIVE real spawners, all
 * synchronous and one child at a time. Four more files only
 * `vi.mock('node:child_process', ...)` and spawn nothing real —
 * shield/llm.test.ts and shield/llm-backend.test.ts (the two the unit
 * counted), plus adapters/docker.test.ts and
 * adapters/child-env-wiring.test.ts; none has the static import, so the
 * enumeration below correctly excludes them.
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
};
