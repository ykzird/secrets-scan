import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // Ensure Vitest can handle ESM dependencies like chalk v5
    // when the project itself is CommonJS
    globals: false,
  },
});
