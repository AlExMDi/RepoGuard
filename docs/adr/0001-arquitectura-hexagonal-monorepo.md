# ADR 0001 — Arquitectura hexagonal en un monorepo pnpm

- Estado: **Propuesto**
- Fecha: 2026-10-04
- Relacionado: [Spec MVP](../specs/mvp.md) §4.3–§4.5 · sustituye a la estructura
  `cli/ backend/ frontend/` de `docs/planning/03-architecture-flow.md` (commit `eaa7334`)

> Nota de numeración: el §8 de la spec reservaba el 0001 para «Solo CLI + Action». Esa
> decisión pasa a ser el 0002 y las siguientes se desplazan una posición, para que cada
> ADR recoja una sola decisión.

## Contexto

RepoGuard es un CLI local-first que escanea un repo en busca de secretos, dependencias
vulnerables y misconfiguraciones (spec §1). El código tiene que convivir con varias
fuerzas a la vez:

- **Mucha E/S distinta y hostil.** Git mediante `execFile`, HTTP a OSV, SQLite para la
  caché, el sistema de ficheros para el baseline, y stdout/stderr. Todo procesa entrada
  no confiable (spec §6).
- **La lógica crítica es pura y hay que poder probarla sin E/S.** `prioritize`,
  `exitCode`, `dedupeSecrets`, `applyBaseline`, `redact` y `fingerprint` son los puntos
  donde un fallo significa filtrar un secreto o romper el gate de CI. La spec (§5.1)
  exige tests unitarios de todas ellas sin E/S, incluido un property test de `redact`.
- **Varias implementaciones por puerto.** Hay tres escáneres y tres reporters (text,
  json, sarif), y la caché tiene que poder desactivarse (`--no-cache`), igual que OSV
  (`--offline`). En los tests, cada adaptador se sustituye por un doble.
- **Dependencias con distinto peso.** SQLite es un módulo nativo; el parser YAML y el
  cliente HTTP solo los necesitan algunos componentes. Un cambio en las reglas de
  secretos no debería obligar a recompilar ni a volver a probar el adaptador de git.
- **Contexto de formación.** Es un proyecto de un desarrollador junior. Los límites de
  la arquitectura tienen que verse en la estructura del repo y que los imponga la
  herramienta, en lugar de depender solo de la disciplina.

El plan anterior (`docs/planning/`) proponía un monorepo `cli/ backend/ frontend/`
organizado alrededor de una API. Al quedar el backend y el dashboard fuera del MVP
(ADR 0002), esa estructura deja de tener sentido.

## Decisión

1. **Arquitectura hexagonal (puertos y adaptadores).**
   - `packages/core` contiene el modelo de dominio (`Finding`, `ScanResult`,
     `Severity`…), los **puertos** (`RepoReader`, `Scanner`, `VulnerabilityDb`,
     `ScanCache`, `BaselineStore`, `Reporter`) y la **lógica pura**
     (`src/{domain,ports,policy}`).
   - `core` **no depende de ningún otro paquete del workspace ni hace E/S**: no importa
     `node:*` ni ninguna librería con efectos. Lo que necesita del entorno (p. ej. el
     hash de `fingerprint`) se le inyecta como función.
   - Escáneres, adaptadores y reporters **implementan** puertos de `core` y solo
     dependen de `core`. Un adaptador no importa a otro.
   - `packages/cli` es la única **raíz de composición**: instancia los adaptadores, los
     inyecta y traduce los argumentos.

2. **Monorepo con pnpm workspaces y un paquete por adaptador**, según el layout de la
   spec §4.5:

   ```
   packages/core                 ← no depende de nada
   packages/scanner-secrets      ─┐
   packages/scanner-deps          │
   packages/scanner-misconfig     │
   packages/adapter-git           ├─ dependen solo de core
   packages/adapter-osv           │
   packages/adapter-sqlite        │
   packages/reporters            ─┘
   packages/cli                  ← depende de todos (composición)
   ```

   Las dependencias apuntan siempre hacia `core`, nunca al revés ni en horizontal.

3. **TypeScript project references** (`tsc -b`): cada paquete tiene su `tsconfig.json`
   con `composite: true` y declara en `references` solo los paquetes de los que depende.
   No se añade ningún orquestador de tareas.

4. **Cómo se hace cumplir.** `packages/core/package.json` no declara dependencias de
   workspace ni de runtime. Con el aislamiento estricto de pnpm (sin hoisting de
   paquetes no declarados), un `import "@repoguard/adapter-git"` desde `core` no
   resuelve y falla en el build. Igual en los adaptadores: solo pueden importar lo que
   declaran.

## Alternativas descartadas

| Alternativa | Por qué se descarta |
|---|---|
| **Mantener `cli/ backend/ frontend/`** (plan `docs/planning/`) | Se organizaba alrededor de una API y una base de datos que ya no existen (ADR 0002). Además, metía todo el motor de escaneo dentro de `cli/`, sin separar lógica pura de E/S. |
| **Un solo paquete con carpetas** (`src/core`, `src/adapters/…`) | Es más simple de montar, pero el límite «core no importa adaptadores» quedaría como una convención que nadie comprueba: un import relativo `../adapters/git` compila sin problema. Con paquetes separados, el gestor de paquetes rechaza esa dependencia. |
| **Arquitectura por capas sin puertos** (escáneres que llaman a git o a OSV directamente) | Los tests de la lógica crítica necesitarían un repo git real o red, lo que contradice §5.1. Tampoco permitiría sustituir la caché o OSV para `--no-cache` y `--offline` sin meter condicionales en el dominio. |
| **Un único paquete `adapters`** con git, OSV y SQLite juntos | Quien solo necesita el adaptador de git cargaría también el módulo nativo de SQLite y el cliente HTTP. Un fallo de compilación nativa bloquearía paquetes que no tienen nada que ver. |
| **Multirepo** (un repo por paquete) | Con un solo desarrollador y paquetes que cambian a la vez (un cambio en `Finding` toca core, escáneres y reporters), coordinar versiones entre repos es puro coste. |
| **Turborepo** | Su cache de tareas no compensa con 9 paquetes pequeños: `tsc -b` ya recompila de forma incremental. Sería una dependencia y una configuración más. |
| **Nx** | Su regla `enforce-module-boundaries` es atractiva, pero Nx es pesado para este tamaño y obliga a aprender su modelo de proyecto. El límite principal ya lo da pnpm. |

## Consecuencias

### Positivas
- La lógica que decide si un secreto se filtra (`redact`) o si el CI pasa (`exitCode`)
  se prueba de forma unitaria, rápida y determinista, sin git, red ni disco.
- Para añadir un escáner, un reporter o un ecosistema basta con crear un paquete nuevo
  que implemente un puerto; `core` no cambia.
- Las dependencias pesadas o con riesgo (SQLite nativo, parser YAML, HTTP) quedan
  aisladas en el paquete que las usa. Su superficie de ataque y su impacto en el build se
  acotan.
- La raíz de composición única (`cli`) deja a la vista qué implementación se usa en cada
  modo (`--offline`, `--no-cache`).

### Negativas / costes
- **Hay más ceremonia.** Son 9 `package.json` y 9 `tsconfig.json`, y cada dependencia
  entre paquetes se declara dos veces (en `package.json` y en `references`). Si se
  desincronizan, el error que da `tsc -b` no siempre es claro.
- **La pureza de E/S de `core` no la vigila ninguna herramienta.** pnpm impide importar
  paquetes no declarados, pero **no** impide `import "node:fs"` ni el uso de `process` o
  `Buffer`, porque los built-ins de Node siempre resuelven. Por ahora depende de la
  revisión (y del agente `architect`). Si aparece una violación, el siguiente paso barato
  es quitar `@types/node` del `tsconfig` de `core` o añadir `no-restricted-imports` en
  ESLint. Ese cambio se recogería en un ADR nuevo.
- **Las dependencias declaradas en el `package.json` raíz** pueden resolverse desde
  cualquier paquete por la resolución ascendente de Node. El raíz solo debe tener
  devDependencies de tooling (TypeScript, ESLint, Vitest), nunca librerías de runtime.
- **Los escáneres son adaptadores, pero casi todo su código es lógica pura** (reglas y
  parsers). Hay que resistir la tentación de moverlos a `core`: dependen de librerías
  (YAML) y de las reglas concretas, que no forman parte del dominio.
- Hay que decidir cómo se publica: el CLI se distribuye como `npx repoguard`, así que
  los paquetes internos tienen que empaquetarse junto a él o publicarse. Queda fuera de
  este ADR.
