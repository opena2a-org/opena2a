import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['__tests__/**/*.test.ts'],
    environment: 'node',
    testTimeout: 10000,
    // Tests share ~/.opena2a/ state files, so run sequentially
    fileParallelism: false,
  },
});
