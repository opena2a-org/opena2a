import { readFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { defineConfig } from 'vitest/config';

// Worker count derived from the process cap of the cgroup the run lives in. On a host with no
// cap (a developer machine, a GitHub runner) this resolves to vitest's default and changes
// nothing. Measured 2026-09-05 in the fleet lane (--pids-limit 512, 16 CPUs) with a 0.5 s
// per-process census at the peak, across three runs with 16, 13 and 9 workers: the peak sat at
// 500, 486 and 484 tasks regardless of the worker count, because the tasks are not the workers.
// At the 484 peak: the vitest main process and its parents about 60; each worker its fork
// (about 7 threads) plus the esbuild service it starts (about 6.5), i.e. 13.5; and the CLI child
// processes the tests spawn, 11 to 14 threads each, with one worker holding 8 children at once
// (a test file that runs several CLI invocations concurrently). A worker's worst case is
// therefore 13.5 + 8 x 13 = 117.5 tasks, and that worst case, not the average, is what the cap
// must fit, because the run only has to fail once: with the default worker count the cgroup
// reached 500 to 508 within three seconds and the next fork failed with `spawn node EAGAIN`,
// which vitest reports once as an unhandled pool error and then waits on without further
// output. max(1, min(cpus, (512 - 60 - 64) / 118)) = 3 here; re-derive the constants when the
// pool, the esbuild service or the tests' spawn fan-out changes.
const BASE_TASKS = 60;
const TASKS_PER_WORKER = 118;
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
