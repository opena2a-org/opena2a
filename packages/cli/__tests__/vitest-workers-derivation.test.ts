/**
 * Pins the worker-cap derivation in ../vitest.workers.ts (QGF-40.AC4): with
 * the concurrent-write fan-out bounded, a 512-pid cgroup must get at least
 * two vitest workers back, and the per-worker constant must keep covering
 * the ceiling the bound actually enforces.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  BASE_TASKS,
  SPAWN_HEADROOM,
  TASKS_PER_WORKER,
  deriveMaxWorkers,
} from '../vitest.workers.js';

/**
 * The ceiling as written in the test file that enforces it. Read from source
 * rather than imported: importing a *.test.ts module would register its
 * tests into this file's collection and run every child-spawning round a
 * second time.
 */
function sourcedMaxLiveChildren(): number {
  const source = fs.readFileSync(
    path.resolve(__dirname, 'shield', 'concurrent-write.test.ts'),
    'utf-8',
  );
  const match = source.match(/^const MAX_LIVE_CHILDREN = (\d+);$/m);
  if (!match) {
    throw new Error('MAX_LIVE_CHILDREN literal not found in shield/concurrent-write.test.ts');
  }
  return Number(match[1]);
}

describe('vitest worker-cap derivation', () => {
  it('QGF-40.AC4 yields at least two workers at pidsMax=512 with four or more CPUs', () => {
    expect(deriveMaxWorkers(512, 4)).toBeGreaterThanOrEqual(2);
    expect(deriveMaxWorkers(512, 16)).toBeGreaterThanOrEqual(2);
    // The contract's arithmetic bound behind that result: at 512 pids, two
    // workers exist only if one worker's worst case fits in half the budget.
    expect(TASKS_PER_WORKER).toBeLessThanOrEqual(
      Math.floor((512 - BASE_TASKS - SPAWN_HEADROOM) / 2),
    );
  });

  it('covers the fan-out ceiling concurrent-write.test.ts actually enforces', () => {
    // Each live child is a tsx process plus the node child it runs the CLI
    // in, about 11 threads each (measured 2026-09-05, fleet-lane census);
    // the worker fork itself is about 7. Raising MAX_LIVE_CHILDREN without
    // re-deriving TASKS_PER_WORKER re-creates the unbounded regression this
    // derivation exists to contain, so it fails here.
    const WORKER_FORK_TASKS = 7;
    const TASKS_PER_LIVE_CHILD = 2 * 11;
    expect(TASKS_PER_WORKER).toBeGreaterThanOrEqual(
      WORKER_FORK_TASKS + sourcedMaxLiveChildren() * TASKS_PER_LIVE_CHILD,
    );
  });

  it('resolves to the vitest default when the cgroup imposes no cap', () => {
    expect(deriveMaxWorkers(null, 16)).toBeUndefined();
  });

  it('never derives below one worker or above the CPU count', () => {
    // A cap tighter than one worker's worst case still has to run the suite.
    expect(deriveMaxWorkers(BASE_TASKS + SPAWN_HEADROOM, 16)).toBe(1);
    // And an enormous cap is still bounded by the machine.
    expect(deriveMaxWorkers(1_000_000, 4)).toBe(4);
  });
});
