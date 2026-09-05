import { readFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { defineConfig } from 'vitest/config';

// Worker count derived from the process cap of the cgroup the run lives in. On a host with no
// cap (a developer machine, a GitHub runner) this resolves to vitest's default and changes
// nothing. Measured 2026-09-05 in the fleet lane (--pids-limit 512, 16 CPUs) with a 0.5 s
// per-process census at the peak, across four runs with 16, 13, 9 and 3 workers: peaks 500,
// 486, 484 and 413. The tasks are mostly not the workers. Fixed cost about 172: the vitest
// main process and its parents about 60 plus an esbuild service pool of 16 processes at about
// 7 threads each, present at every worker count. Per worker: its fork (about 7 threads) plus the
// CLI child processes the file it is running spawns: one test file starts 8 `tsx <cli>` runs at
// once, and each tsx process runs the CLI in a child node process, so 16 processes of about
// 11 threads, i.e. a worst case of about 7 + 16 x 11 = 183 per worker (measured: one worker
// holding 8 tsx children and their 8 node children at the 409-task peak with 2 workers). The cap fits the worst case because the run only has to fail once: with
// the default worker count the cgroup reached 500 to 508 within three seconds and the next
// fork failed with `spawn node EAGAIN`, which vitest reports once as an unhandled pool error
// and then waits on without further output. max(1, min(cpus, (512 - 172 - 64) / 183)) = 1
// here: two workers running that file at once would reach about 538. This is a containment, not a fix: the lever is the per-file fan-out, and bounding it
// where the tests spawn it would give the workers back. Re-derive the constants when the pool,
// the esbuild service or the tests' spawn fan-out changes.
const BASE_TASKS = 172;
const TASKS_PER_WORKER = 183;
const SPAWN_HEADROOM = 64;

function cgroupPidsMax(): number | null {
  try {
    const raw = readFileSync('/sys/fs/cgroup/pids.max', 'utf8').trim();
    if (raw === 'max') return null;
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

const pidsMax = cgroupPidsMax();
const maxWorkers =
  pidsMax === null
    ? undefined
    : Math.max(
        1,
        Math.min(availableParallelism(), Math.floor((pidsMax - BASE_TASKS - SPAWN_HEADROOM) / TASKS_PER_WORKER)),
      );

export default defineConfig({
  test: {
    include: ['__tests__/**/*.test.ts'],
    environment: 'node',
    testTimeout: 10000,
    ...(maxWorkers === undefined ? {} : { maxWorkers }),
  },
});
