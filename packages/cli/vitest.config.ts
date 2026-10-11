import { availableParallelism } from 'node:os';
import { defineConfig } from 'vitest/config';
// The derivation and its measured constants live in vitest.workers.ts, where
// __tests__/vitest-workers-derivation.test.ts can import and pin them
// without reading a live cgroup file.
import { cgroupPidsMax, deriveMaxWorkers } from './vitest.workers.js';

const maxWorkers = deriveMaxWorkers(cgroupPidsMax(), availableParallelism());

export default defineConfig({
  test: {
    include: ['__tests__/**/*.test.ts'],
    // No test reaches a non-loopback host: see the file for why.
    setupFiles: ['__tests__/setup/offline-fetch.ts'],
    environment: 'node',
    testTimeout: 10000,
    ...(maxWorkers === undefined ? {} : { maxWorkers }),
  },
});
