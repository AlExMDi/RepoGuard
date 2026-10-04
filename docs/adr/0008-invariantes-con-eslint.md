# ADR 0008 — Invariantes de arquitectura y de no filtrado con ESLint

- Estado: **Propuesto**
- Fecha: 2026-10-04
- Relacionado: [ADR 0001](0001-arquitectura-hexagonal-monorepo.md) (consecuencias
  negativas) · [Spec finding-runscan](../specs/finding-runscan.md) §2.1, §5.4

> Numeración: la nota de ADR 0001 reserva del 0002 al 0007 para las decisiones del §8 de
> la spec MVP. Este es el siguiente número libre.

## Contexto

ADR 0001 deja dos huecos que ninguna herramienta vigila:

1. **Pureza de `core`.** pnpm impide importar paquetes no declarados, pero los built-ins
   de Node (`node:fs`, `fs`, `process`, `Buffer`) siempre resuelven. Hasta ahora, una
   importación de E/S en core solo se detectaba en la revisión.
2. **Acceso al secreto en claro.** La spec finding-runscan §2.1 introduce `SecretValue`,
   un valor opaco cuyo contenido solo se obtiene con `unsafeReveal()`. Para que la opacidad
   sirva de algo, ese método solo puede llamarse desde `policy/fingerprint.ts` y desde
   `scanner-secrets`.

La spec proponía un test de vitest que hiciera grep del código. Ese test tendría que
importar `node:fs`, así que no podría vivir en core, y solo fallaría al ejecutar los tests.

## Decisión

Las dos invariantes se hacen cumplir en `eslint.config.js`:

- En `packages/core/**` (todas las extensiones fuente):
  - `no-restricted-imports` con `node:*`, todos los `builtinModules` (con y sin subruta)
    y `@repoguard/*`.
  - `no-restricted-globals` con `process` y `Buffer`.
- En `packages/**/*.{ts,mts,cts,js,mjs,cjs}` (no solo `src/`), `no-restricted-syntax`
  sobre **cualquier mención** de `unsafeReveal`: el identificador (`Identifier`), una
  clave de texto (`Literal`) o una plantilla (`TemplateElement`). Bloquear solo la
  llamada `x.unsafeReveal()` no basta: `.call`, `.bind`, la desestructuración y los alias
  la esquivaban (lo detectó la revisión de la rama `feat/3-core-domain`). La regla se
  desactiva solo en `core/src/domain/secret-value.ts` (la definición),
  `core/src/policy/fingerprint.ts`, `core/src/domain/secret-value.test.ts` y
  `scanner-secrets/src/**`.

La lista de built-ins se obtiene en tiempo de configuración de `node:module`, en vez de
escribirla a mano, para que no se quede desfasada.

## Alternativas descartadas

| Alternativa | Por qué se descarta |
|---|---|
| Test con grep (lo que proponía la spec) | Necesita `node:fs` y tendría que vivir fuera de core. Un grep de texto no detecta `x["unsafeReveal"]` ni imports de varias líneas, y no da feedback en el editor. |
| Confiar en `tsc` (`types: []`, sin `@types/node`) | Hoy `tsc` ya rechaza `import "fs"` y `process`, pero solo por casualidad: basta con que algún paquete arrastre `@types/node` para que dejen de fallar. Además el error («cannot find module») no explica *por qué* está prohibido y no cubre `unsafeReveal`. Se mantiene como segunda barrera. |
| `eslint-plugin-boundaries` / Nx | Es una dependencia más para dos reglas que ESLint ya trae de serie. |

## Consecuencias

- La regla protege frente a **errores accidentales**, no frente a alguien que quiera
  saltársela a propósito: `v["unsafe" + "Reveal"]` sigue pasando. Para eso está la revisión.
- `pnpm lint` (y por tanto CI) falla ante cualquier violación, y el editor la marca
  mientras se escribe. El mensaje cita el ADR.
- Un `// eslint-disable` puede saltarse la regla. Es visible en el diff y lo revisan los
  agentes `architect` y `security-reviewer`.
- Si se añade un fichero que necesite `unsafeReveal`, se amplía la lista de excepciones
  en `eslint.config.js`, y ese cambio también queda visible en el diff.
