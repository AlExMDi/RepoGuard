import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import { defineConfig } from "eslint/config";
import { builtinModules } from "node:module";
import tseslint from "typescript-eslint";

// Invariantes de arquitectura y de no filtrado (ADR 0008).

// Regex anclada y no `group`: los patrones `group` siguen la sintaxis de .gitignore, así que
// el built-in "domain" bloquearía también "../domain/finding".
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const nodeBuiltin = `^(node:.*|(${builtinModules.map(escape).join("|")})(/.*)?)$`;

// Cualquier mención de unsafeReveal, no solo la llamada: así también se bloquean
// la desestructuración, .call/.bind, los alias y el acceso con una clave de texto.
const unsafeRevealMessage =
  "unsafeReveal solo se permite en policy/fingerprint y en scanner-secrets (ADR 0008).";
const unsafeRevealUse = [
  { selector: "Identifier[name='unsafeReveal']", message: unsafeRevealMessage },
  { selector: "Literal[value='unsafeReveal']", message: unsafeRevealMessage },
  { selector: "TemplateElement[value.cooked='unsafeReveal']", message: unsafeRevealMessage },
];

// La regla cubre también .js/.mts/.cts y ficheros fuera de src/.
const allSources = ["packages/**/*.{ts,mts,cts,js,mjs,cjs}"];

export default defineConfig(
  { ignores: ["**/dist", "**/*.d.ts"] },
  js.configs.recommended,
  tseslint.configs.strict,
  {
    files: allSources,
    rules: { "no-restricted-syntax": ["error", ...unsafeRevealUse] },
  },
  {
    files: [
      "packages/core/src/domain/secret-value.ts",
      "packages/core/src/policy/fingerprint.ts",
      "packages/core/src/domain/secret-value.test.ts",
      "packages/scanner-secrets/src/**/*.ts",
    ],
    rules: { "no-restricted-syntax": "off" },
  },
  {
    // core no hace E/S ni depende de otros paquetes (ADR 0001).
    files: ["packages/core/**/*.{ts,mts,cts,js,mjs,cjs}"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              regex: nodeBuiltin,
              message: "core no hace E/S: inyecta lo que necesites como puerto (ADR 0001).",
            },
            {
              group: ["@repoguard/*"],
              message: "core no depende de otros paquetes del monorepo (ADR 0001).",
            },
          ],
        },
      ],
      "no-restricted-globals": [
        "error",
        { name: "process", message: "core no accede al entorno (ADR 0001)." },
        { name: "Buffer", message: "Usa Uint8Array en core (ADR 0001)." },
      ],
    },
  },
  // Último: desactiva las reglas de estilo que chocarían con Prettier.
  prettier,
);
