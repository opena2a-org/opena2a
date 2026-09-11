import { readFileSync } from 'node:fs';

// Worker count derived from the process cap of the cgroup the run lives in. On a host with no
// cap (a developer machine, a GitHub runner) this resolves to vitest's default and changes
// nothing.
//
// Measured 2026-09-05 in the fleet lane (--pids-limit 512, 16 CPUs) with a 0.5 s per-process
// census at the peak, before the fan-out bound, across runs with 16, 13, 9, 3, 2 and 1
// workers: peaks 500, 486, 484, 413, 409 and 396. The tasks are mostly not the workers.
// Fixed cost about 172: the vitest main process and its parents about 60 plus an esbuild
// service pool of 16 processes at about 7 threads each, present at every worker count.
//
// Per worker, with the fan-out bound in place: the worker fork (about 7 threads) plus the
// children of the one file that spawns concurrently —
// __tests__/shield/concurrent-write.test.ts holds at most MAX_LIVE_CHILDREN = 4 `tsx <cli>`
// children live at once (QGF-40.AC1; the census measured about 11 threads per tsx process and
// per the node child each tsx runs the CLI in), so the worst case is
// 7 + (2 x 4) x 11 = 95 tasks per worker, re-derived from the same per-process figures the
// unbounded 183 (7 + 16 x 11) was measured from. max(1, min(cpus, (512 - 172 - 64) / 95)) = 2
// in that lane: the bound gives a worker back where the unbounded fan-out left 1 of 16.
// Confirm with the census loop from qgf QGF-40.AC6 whenever these constants change:
//   while :; do cat /sys/fs/cgroup/pids.current; sleep 0.5; done
// during one full `npx vitest run` in packages/cli; the peak must stay at least
// SPAWN_HEADROOM below pids.max.
//
// Re-derive the constants when the pool, the esbuild service or the tests' spawn fan-out
// changes; __tests__/vitest-workers-derivation.test.ts pins the arithmetic (QGF-40.AC4) and
// fails if MAX_LIVE_CHILDREN grows past what TASKS_PER_WORKER covers.
export const BASE_TASKS = 172;
export const TASKS_PER_WORKER = 95;
export const SPAWN_HEADROOM = 64;

export function cgroupPidsMax(): number | null {
  try {
    const raw = readFileSync('/sys/fs/cgroup/pids.max', 'utf8').trim();
    if (raw === 'max') return null;
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

/**
 * The worker cap for a given cgroup pid limit and CPU count; `undefined`
 * (vitest's default) when the cgroup imposes no limit. Pure so the derivation
 * is assertable without reading a live cgroup file.
 */
export function deriveMaxWorkers(pidsMax: number | null, cpus: number): number | undefined {
  if (pidsMax === null) return undefined;
  return Math.max(
    1,
    Math.min(cpus, Math.floor((pidsMax - BASE_TASKS - SPAWN_HEADROOM) / TASKS_PER_WORKER)),
  );
}
