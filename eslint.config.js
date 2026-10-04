import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
  { ignores: ["**/dist", "**/*.d.ts"] },
  js.configs.recommended,
  tseslint.configs.strict,
  // Último: desactiva las reglas de estilo que chocarían con Prettier.
  prettier,
);
