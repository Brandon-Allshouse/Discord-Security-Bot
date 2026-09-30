import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Integration tests start a real Postgres container.
    testTimeout: 30_000,
    hookTimeout: 120_000,
  },
});
