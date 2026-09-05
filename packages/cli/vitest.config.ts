import { readFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { defineConfig } from 'vitest/config';

// Worker count derived from the process cap of the cgroup the run lives in. On a host with no
// cap (a developer machine, a GitHub runner) this resolves to vitest's default and changes
// nothing. Measured 2026-09-05 in the fleet lane (--pids-limit 512, 16 CPUs) with a 0.5 s
// per-process census at the peak: the vitest main process and its parents hold about 60 tasks;
// each forked worker costs about 33 (its own 7 threads, the esbuild service it starts, and the
// CLI child processes the tests spawn, 11 to 14 threads each), measured as (486 - 60) / 13 at
// 13 workers; the largest burst above that linear model was 21 tasks, so 64 is kept as headroom
// for a test that spawns more than one child at once. With the default worker count (one per
// CPU) the cgroup reached 500 to 508 of 512 within three seconds and the next fork failed with
// `spawn node EAGAIN`, which vitest reports once as an unhandled pool error and then waits on
// without further output. Re-derive the three constants when the pool or the tests change.
const BASE_TASKS = 60;
const TASKS_PER_WORKER = 33;
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
