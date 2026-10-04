import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/*/src/**/*.test.ts"],
    // Aún no hay tests: sin esto `vitest run` termina con exit 1.
    passWithNoTests: true,
  },
});
