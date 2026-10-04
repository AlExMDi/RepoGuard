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

const unsafeRevealCall = [
  {
    selector: "CallExpression[callee.property.name='unsafeReveal']",
    message: "unsafeReveal solo se permite en policy/fingerprint y en scanner-secrets (ADR 0008).",
  },
  {
    selector: "MemberExpression[computed=true][property.value='unsafeReveal']",
    message: "unsafeReveal solo se permite en policy/fingerprint y en scanner-secrets (ADR 0008).",
  },
];

export default defineConfig(
  { ignores: ["**/dist", "**/*.d.ts"] },
  js.configs.recommended,
  tseslint.configs.strict,
  {
    files: ["packages/*/src/**/*.ts"],
    rules: { "no-restricted-syntax": ["error", ...unsafeRevealCall] },
  },
  {
    files: [
      "packages/core/src/policy/fingerprint.ts",
      "packages/core/src/domain/secret-value.test.ts",
      "packages/scanner-secrets/src/**/*.ts",
    ],
    rules: { "no-restricted-syntax": "off" },
  },
  {
    // core no hace E/S ni depende de otros paquetes (ADR 0001).
    files: ["packages/core/src/**/*.ts"],
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
