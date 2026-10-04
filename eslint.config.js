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
const mentions = (name, message) => [
  { selector: `Identifier[name='${name}']`, message },
  { selector: `Literal[value='${name}']`, message },
  { selector: `TemplateElement[value.cooked='${name}']`, message },
];
const unsafeRevealUse = mentions(
  "unsafeReveal",
  "unsafeReveal solo se permite en policy/fingerprint y en scanner-secrets (ADR 0008).",
);
// hasPrefix y occursIn responden preguntas sobre el valor: usados en bucle, servirían para
// reconstruirlo. Solo los necesita la validación de eventos.
const oracleUse = ["hasPrefix", "occursIn"].flatMap((name) =>
  mentions(name, `${name} solo se permite en policy/sanitize-event (ADR 0008).`),
);

// La regla cubre también .js/.mts/.cts y ficheros fuera de src/.
const allSources = ["packages/**/*.{ts,mts,cts,js,mjs,cjs}"];

export default defineConfig(
  { ignores: ["**/dist", "**/*.d.ts"] },
  js.configs.recommended,
  tseslint.configs.strict,
  // Cada fichero recibe solo el permiso que necesita: revelar el valor o usar los oráculos.
  {
    files: allSources,
    rules: { "no-restricted-syntax": ["error", ...unsafeRevealUse, ...oracleUse] },
  },
  {
    files: ["packages/core/src/policy/fingerprint.ts", "packages/scanner-secrets/src/**/*.ts"],
    rules: { "no-restricted-syntax": ["error", ...oracleUse] },
  },
  {
    files: ["packages/core/src/policy/sanitize-event.ts"],
    rules: { "no-restricted-syntax": ["error", ...unsafeRevealUse] },
  },
  {
    files: [
      "packages/core/src/domain/secret-value.ts",
      "packages/core/src/domain/secret-value.test.ts",
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
