# Spec — Modelo `Finding` y caso de uso `runScan`

Estado: borrador para revisión · Fecha: 2026-10-04 · Rama: `feat/3-core-domain`
Depende de: [Spec MVP](mvp.md) §2.1, §2.5–§2.6, §4.2–§4.4, §7 · [ADR 0001](../adr/0001-arquitectura-hexagonal-monorepo.md)

> Esta spec **concreta** el modelo de mvp.md §4.3. Los dos cambios marcados ⚠ (avisos
> estructurados en vez de `string[]`, y `schemaVersion` y `warnings` globales en
> `ScanResult`) ya están incorporados a mvp.md. Las decisiones marcadas **[por defecto]** no se
> discutieron en la entrevista; revísalas.

## 1. Problema

`packages/core` está vacío (`export {}`). Antes de escribir cualquier escáner o reporter
hace falta:

1. El **modelo de dominio** (`Finding`, `ScanResult`, `Warning`…) que comparten todos los
   paquetes y que define el contrato JSON estable.
2. El **caso de uso `runScan`**, que orquesta los puertos: carga el baseline, ejecuta los
   escáneres, convierte las coincidencias de secretos en hallazgos redactados, deduplica,
   aplica el baseline, prioriza, calcula el exit code y, si se pide, actualiza el baseline.

El punto delicado es que `runScan` es **el único sitio del sistema por el que pasa el valor
de un secreto en claro** después del escáner. Si el modelo permite que ese valor llegue a
un `Finding`, cualquier reporter, log o `JSON.stringify` lo filtra.

## 2. Alcance

### 2.1 Transporte del secreto: `SecretValue` opaco
- Los escáneres de secretos **no** emiten `Finding`, sino `RawSecretMatch`, que contiene un
  `SecretValue`.
- `SecretValue` es una clase de core con el valor en un campo privado (`#value`).
  `toString()`, `toJSON()`, `valueOf()` y `[Symbol.for("nodejs.util.inspect.custom")]`
  devuelven `"[REDACTED]"`. *Por qué: así un `console.log`, una plantilla o un
  `JSON.stringify` accidentales no filtran nada; `Symbol.for` no requiere importar
  `node:util`, de modo que core sigue sin E/S.*
- El valor solo se obtiene con `unsafeReveal()`. **Solo** lo pueden llamar `fingerprint` y
  el escáner que lo crea. Lo comprueba un test que hace grep del código fuente (§5.4).
- `runScan` calcula `fingerprint` y `redact` y **descarta** el `SecretValue` antes de
  construir el `Finding`. Ningún tipo de `Finding` o `ScanResult` admite un `SecretValue`.

### 2.2 Aislamiento de fallos por categoría
- Cada escáner se ejecuta dentro de su propio `try/catch`. Si lanza una excepción:
  - Los hallazgos que ya había emitido **se conservan**. *Por qué: un secreto ya
    encontrado no deja de ser real porque la regla siguiente falle.*
  - Su categoría queda `status: "incomplete"` con el aviso `SCANNER_FAILED`. El aviso
    **no incluye** el mensaje ni el stack de la excepción, porque podrían contener la
    línea que se estaba analizando.
  - Las demás categorías continúan.
- Los escáneres se ejecutan **de forma concurrente** **[por defecto]**. *Por qué: la
  latencia de OSV (hasta 5 s) se solapa con el escaneo de secretos; el orden final no
  depende de la concurrencia porque `prioritize` lo fija.*
- **Validación del contrato en runtime** (`policy/sanitize-event.ts`): los tipos de
  TypeScript solo existen al compilar, así que cada evento se trata como `unknown`, se
  valida y se **reconstruye campo a campo** (lista blanca). Los campos extra se
  descartan. Es violación de contrato (`SCANNER_CONTRACT_VIOLATION`, se deja de leer ese
  escáner y su categoría queda `incomplete`):
  - un hallazgo de otra categoría, o un secreto emitido por un escáner que no es de
    secretos;
  - una severidad, código de aviso, `reason` o `kind` fuera de su enum. *Por qué: con una
    severidad desconocida (p. ej. `"CRITICAL"` de OSV), `exitCode` no la contaría y el
    gate de CI pasaría en silencio. Lo desconocido bloquea, no deja pasar.*
  - un `ruleId` con espacios o caracteres de control (en secretos, solo kebab-case: entra
    en el hash del fingerprint);
  - líneas o columnas que no son enteros ≥ 1, o un `count` negativo;
  - un `publicPrefix` de más de 12 caracteres o que no es prefijo real del secreto
    (`SecretValue.hasPrefix`, sin sacar el valor en claro), o que deja menos de 16
    caracteres ocultos (con menos, el fingerprint del baseline commiteado se podría
    atacar por fuerza bruta);
  - un `title`, `kindLabel`, `ruleId`, `path` o `commit` de un secreto que contiene el
    valor completo (`SecretValue.occursIn`);
  - un valor que no es un `SecretValue` auténtico (`SecretValue.isGenuine` comprueba la
    marca privada: un Proxy o una imitación no pasan; la longitud se lee con
    `SecretValue.lengthOf`, que una subclase no puede falsear);
  - textos por encima de su límite (`title` 512, `kindLabel` 64, rutas/URLs/nombres
    4096) o más de 100 `aliases`.
- **Cada campo se lee una sola vez** (desestructurando) y se valida y copia esa variable
  local. *Por qué: si se leyera dos veces, un getter podría devolver un valor válido al
  validar y otro distinto al copiar (TOCTOU).*

### 2.3 Identificador estable (`Finding.id`)
| Categoría | `id` |
|---|---|
| secret | `fingerprint` (mvp §7, con sal) |
| dependency | `hash(["dependency", osvId, lockfile, ecosystem, name, version])` |
| misconfig | `hash(["misconfig", ruleId, path, anchor])` |

- `anchor` es una **clave semántica** que da la regla y que no depende del número de
  línea: el nombre del job y el índice del step en GHA, el índice de la instrucción
  `FROM`/`ADD` en el Dockerfile o `""` en `env-file-committed`. *Por qué: si se añade
  una línea encima, el hallazgo no reaparece como nuevo ni rompe el baseline.*
- La entrada al hash se codifica como un array JSON canónico **[por defecto]**. *Por qué:
  concatenar con separadores sería ambiguo si un campo contiene el separador; un array
  JSON no lo es.*
- Los ids de deps y misconfig no llevan sal, porque no derivan de material secreto.

### 2.4 Deduplicación de secretos y «primera aparición»
- Cada `RawSecretMatch` lleva un `ordinal: number` que asigna `RepoReader`: el orden
  topológico de commits, del más antiguo al más reciente (`rev-list --topo-order
  --reverse`), y dentro de cada commit por ruta y luego por línea. Las ocurrencias del árbol
  de trabajo van **detrás** de todo el historial.
- `dedupeSecrets` agrupa por fingerprint. La ubicación del hallazgo es la del **ordinal
  menor**, `occurrences` es el número de coincidencias e `inWorkingTree` vale true si
  alguna es del árbol. *Por qué: la ubicación que importa para la rotación es dónde se
  filtró originalmente.*
- A igual ordinal (no debería ocurrir), se desempata por `(path, line, column)` para que
  la salida sea determinista.

### 2.5 Baseline
- **Lectura**: el resultado tiene tres variantes: `missing`, `valid` e `invalid`. Si es
  `invalid`, se emite el aviso `BASELINE_INVALID`, no se suprime nada y la sal se genera
  al azar (mvp §2.5).
- **Sal**: se usa la del baseline si es válido; si no, `random(32)` (inyectado). La sal
  del baseline es entrada no confiable: se normaliza a minúsculas y, si no son 32 bytes
  en hex, el baseline entero cuenta como `invalid`. *Por qué: una sal que `fingerprint`
  rechazara haría fallar todas las coincidencias y dejaría ciega la categoría de secretos.*
  Igual con los fingerprints de las entradas (64 hex, normalizados a minúsculas para no
  perder su nota) y con la forma del objeto: lo valida `policy/sanitize-adapter.ts`, y
  cualquier campo inválido invalida el baseline entero.
- **`--update-baseline`**:
  - Se **niega** (exit 2, aviso `BASELINE_UPDATE_REFUSED` con un motivo) si:
    - alguna categoría está `incomplete` o `skipped`, o se usó `--no-history`
      (`motivo: "partial-scan"`). *Por qué: si se reescribe con un scan parcial, se borran
      en silencio entradas que el scan no pudo ver.*
    - el baseline existente es `invalid` (`motivo: "invalid-baseline"`). *Por qué: se
      perderían la sal y las notas, y al cambiar la sal cambian todos los fingerprints.*
  - En otro caso, las entradas pasan a ser **exactamente** los hallazgos actuales
    (suprimidos o no). Se **conservan la sal** y la `note` de las entradas que siguen
    vigentes, y desaparecen las obsoletas. Las entradas se ordenan por `fingerprint`
    **[por defecto]**, para que el diff del PR sea mínimo y estable.
  - Tras escribir, todos los hallazgos quedan `suppressed: true` y el exit code es 0.
  - Si `save` lanza, el informe se devuelve igualmente, con el aviso global
    `BASELINE_SAVE_FAILED` (sin el mensaje del error), nada suprimido y exit 2.

### 2.6 Avisos estructurados ⚠ (incorporado a mvp §4.3)
- Se usa `Warning = { code: WarningCode; path?: string; count?: number; reason?: string }`.
  `code` y `reason` son enums cerrados. **No existe ningún campo de texto libre.** *Por
  qué: así no se puede meter contenido de una línea en un aviso; la ruta se sanea en el
  reporter, que es quien genera el texto.* El tipo lo garantiza al compilar y
  `sanitizeWarning` en runtime (§2.2).
- Hay avisos por categoría (`categories[c].warnings`) y avisos globales
  (`ScanResult.warnings`) para lo que no pertenece a ninguna: caché, baseline y clon
  superficial.

### 2.7 Lo que hace `runScan`, en orden
1. Carga el baseline (`BaselineStore.load`) y decide la sal.
2. Ejecuta los escáneres habilitados de forma concurrente, cada uno aislado (§2.2).
   Los deshabilitados (`--offline` → deps) quedan `skipped` sin ejecutarse.
3. Convierte cada `RawSecretMatch` en un borrador: `fingerprint` + `redact` y se descarta
   el `SecretValue`.
4. `dedupeSecrets` → `applyBaseline` → `prioritize`.
5. Calcula `exitCode(findings, failOn, categories)` (mvp §4.2).
6. Si `updateBaseline`: aplica §2.5 y guarda con `BaselineStore.save`.
7. Devuelve `{ result: ScanResult, exitCode }`. **No renderiza ni escribe en stdout**; eso
   lo hace `cli` con el `Reporter` elegido.

Los errores fatales (no es un repo git; git ausente; `describe()` lanza o devuelve una
forma inválida → `REPO_ERROR`; un escáner con una categoría desconocida →
`INVALID_SCANNER`)
**no** se lanzan como excepción: se devuelven como `{ kind: "fatal", code }` con exit 2
**[por defecto]**. `runScan` no lanza nunca: los fallos de los adaptadores se convierten en
avisos o fatales, siempre sin el mensaje del error. *Por qué: el CLI
no tiene que hacer `catch` genéricos que podrían imprimir el mensaje de una excepción con
datos del repo.*

## 3. No-objetivos
- Escáneres, adaptadores y reporters concretos: aquí solo se definen sus puertos.
- Borrar el secreto de la memoria: los strings de JS son inmutables y el GC decide.
  `SecretValue` protege frente a la **serialización accidental**, no frente a un volcado
  de memoria.
- Cancelación o timeout global del scan: cada adaptador gestiona sus propios timeouts
  (OSV: 5 s).
- Streaming del informe: se necesita la lista completa para ordenarla. La memoria es
  O(hallazgos), no O(repo).
- Fusión de baselines en conflictos de merge.

## 4. Interfaces y ficheros afectados

### 4.1 Modelo (`packages/core/src/domain/`)
```ts
// finding.ts — igual que mvp §4.3, salvo lo indicado
type Severity = "critical" | "high" | "medium" | "low";
type Category = "secret" | "dependency" | "misconfig";
interface Finding { /* mvp §4.3 sin cambios */ }

// secret-value.ts
class SecretValue {
  constructor(value: string);
  unsafeReveal(): string;
  get length(): number;
  toString(): "[REDACTED]"; toJSON(): "[REDACTED]";
}

// raw-secret-match.ts
interface RawSecretMatch {
  ruleId: string; severity: Severity; title: string;
  publicPrefix: string | null;            // null → regla sin prefijo (PEM)
  kindLabel: string;                       // p. ej. "private key, RSA"
  value: SecretValue;
  location: { path: string; line: number; column: number; commit?: string };
  inWorkingTree: boolean;
  ordinal: number;
}

// warning.ts ⚠
type WarningCode =
  | "SCANNER_FAILED" | "SCANNER_CONTRACT_VIOLATION"
  | "FILE_TOO_LARGE" | "BINARY_SKIPPED" | "LINE_TRUNCATED"
  | "UNPINNED_DEPENDENCIES" | "LOCKFILE_INVALID" | "REQUIREMENTS_ESCAPE"
  | "OSV_UNAVAILABLE" | "SHALLOW_CLONE" | "CACHE_RESET"
  | "BASELINE_INVALID" | "BASELINE_UPDATE_REFUSED" | "BASELINE_SAVE_FAILED";
interface Warning { code: WarningCode; path?: string; count?: number;
  reason?: "partial-scan" | "invalid-baseline" }

// scan-result.ts ⚠
interface ScanResult {
  schemaVersion: 1;
  tool; target; durationMs;                // mvp §4.3
  categories: Record<Category, { status: "complete" | "incomplete" | "skipped"; warnings: Warning[] }>;
  warnings: Warning[];                      // nuevo: globales
  findings: Finding[];                      // ordenados (mvp §2.6)
}
```

### 4.2 Puertos (`packages/core/src/ports/`)
```ts
type ScannerEvent =
  | { type: "finding"; finding: Omit<Finding, "id" | "suppressed" | "secret">; anchor: string }
  | { type: "secret"; match: RawSecretMatch }
  | { type: "warning"; warning: Warning }
  | { type: "status"; status: "incomplete" };  // p. ej. OSV caído

// Lo que runScan necesita del repo. Asíncrono porque exige ejecutar git, y devuelve el
// fallo como valor. Los métodos de lectura (mvp §4.4) se añaden con los escáneres.
type RepoDescription = { kind: "ok"; info: RepoInfo }
  | { kind: "fatal"; code: "NOT_A_GIT_REPO" | "GIT_MISSING" | "REPO_ERROR" };
interface RepoReader { describe(): Promise<RepoDescription> }

interface Scanner { readonly category: Category;
  scan(ctx: ScanContext): AsyncIterable<ScannerEvent> }

type BaselineLoad = { kind: "missing" } | { kind: "invalid" }
  | { kind: "valid"; baseline: Baseline };
interface BaselineStore { load(): Promise<BaselineLoad>; save(b: Baseline): Promise<void> }

type Hasher = (bytes: Uint8Array) => string;   // hex SHA-256, lo inyecta cli
type RandomBytes = (n: number) => Uint8Array;
type Clock = () => number;                     // ms, para durationMs
```
*Por qué inyectar `Clock` y `RandomBytes`: `Date.now()` y `crypto` no son E/S en sentido
estricto, pero hacen que los tests no sean deterministas. Con `expected.json` comparado por
igualdad exacta, el determinismo es obligatorio.*

### 4.3 Caso de uso (`packages/core/src/use-cases/run-scan.ts`)
```ts
interface RunScanDeps { scanners: Scanner[]; baseline: BaselineStore;
  hash: Hasher; random: RandomBytes; clock: Clock;
  repo: Pick<RepoReader, "describe"> }
interface RunScanOptions { failOn: Severity | "none"; history: boolean;
  skipped: Category[]; updateBaseline: boolean; toolVersion: string; rulesetVersion: string }
type RunScanOutcome =
  | { kind: "ok"; result: ScanResult; exitCode: 0 | 1 | 2 }
  | { kind: "fatal"; code: "NOT_A_GIT_REPO" | "GIT_MISSING" | "REPO_ERROR" | "INVALID_SCANNER";
      exitCode: 2 };
function runScan(deps: RunScanDeps, opts: RunScanOptions): Promise<RunScanOutcome>;
```

### 4.4 Ficheros
```
packages/core/src/domain/{finding,secret-value,raw-secret-match,warning,scan-result,baseline}.ts
packages/core/src/ports/{scanner,baseline-store,repo-reader,crypto,clock}.ts
packages/core/src/policy/{fingerprint,redact,secret-draft,dedupe-secrets,apply-baseline,prioritize,exit-code,finding-id,update-baseline,sanitize-event,sanitize-adapter,guards}.ts
packages/core/src/use-cases/run-scan.ts          ← carpeta nueva (ver §7)
packages/core/src/index.ts                        reexporta la API pública
packages/core/src/**/*.test.ts                    tests junto al código (vitest.config.ts solo busca en src/)
packages/core/src/testing/{fakes,findings}.ts     dobles y helpers de test (no se exportan desde index.ts)
```

## 5. Casos de test (los tests van primero)

### 5.1 `SecretValue`
- `String(v)`, `` `${v}` ``, `JSON.stringify({v})`, `util.inspect(v)` (este último en un
  test de cli, porque core no importa `node:util`) → nunca contienen el valor.
- Property test: para un valor aleatorio, ninguna de esas serializaciones lo contiene.

### 5.2 Políticas puras
- `finding-id`: es estable aunque cambie la línea; cambia si cambia el anchor, la ruta o la
  versión; dos tuplas distintas cuya concatenación coincide (`["a","bc"]` vs `["ab","c"]`)
  dan ids distintos.
- `dedupeSecrets`: 3 commits + árbol → 1 hallazgo, `occurrences=4`, `inWorkingTree=true` y
  la ubicación del ordinal menor; la entrada desordenada da la misma salida.
- `update-baseline`: conserva la sal y las notas; elimina las entradas obsoletas; las
  entradas salen ordenadas por fingerprint; se niega con una categoría
  `incomplete`/`skipped`, con `history=false` y con un baseline `invalid`.
- `prioritize`, `exitCode`, `redact` y `applyBaseline`: los casos de mvp §5.1.

### 5.3 `runScan` con dobles en memoria
- Camino feliz: 3 escáneres falsos → `ScanResult` ordenado y exit code correcto.
- Un escáner lanza una excepción tras emitir 1 hallazgo → el hallazgo se conserva, la
  categoría queda `incomplete` con `SCANNER_FAILED`, las demás quedan `complete` y el exit
  code es 1 si el hallazgo ≥ umbral (2 si no).
- El mensaje de la excepción contiene un secreto falso → no aparece en
  `JSON.stringify(outcome)`.
- Un escáner emite una categoría ajena → `SCANNER_CONTRACT_VIOLATION`.
- `skipped: ["dependency"]` → el escáner de deps **no se invoca** y queda `skipped`.
- El escáner de deps emite `status: incomplete` → exit 2 sin hallazgos y exit 1 con un
  secreto high.
- Baseline `invalid` → aviso global, nada suprimido y sal aleatoria.
- `updateBaseline` en un scan completo → `save` se llama una vez, todo queda suprimido y
  el exit code es 0. En un scan parcial → `save` no se llama y el exit code es 2.
- Determinismo: los escáneres emiten en órdenes distintos (concurrencia simulada) y el
  `ScanResult` sale idéntico byte a byte (con `clock` fijo).
- `kind: "fatal"`, cuando `repo` indica que no es un repo.

### 5.4 Invariantes del paquete
- **No filtrado**: en todos los tests de `runScan`, `JSON.stringify(outcome)` y los
  argumentos de `save` no contienen ningún valor de `SecretValue` creado en el test.
- **Uso de `unsafeReveal`** y **pureza de core**: los hace cumplir ESLint, no un test
  ([ADR 0008](../adr/0008-invariantes-con-eslint.md)). `pnpm lint` falla si se llama a
  `unsafeReveal` fuera de `policy/fingerprint.ts`, `secret-value.test.ts` y
  `packages/scanner-secrets/`, y si core importa un built-in de Node (con o sin `node:`),
  otro paquete `@repoguard/*`, `process` o `Buffer`.

## 6. Riesgos de seguridad

| Riesgo | Mitigación |
|---|---|
| Secreto en claro en un `Finding`, un log o un error | `SecretValue` opaco (§2.1); el tipo `Finding` no lo admite; test de no filtrado (§5.4) |
| Mensaje de excepción con contenido de una línea | `SCANNER_FAILED` sin mensaje ni stack; los fatales son valores, no excepciones |
| Avisos con texto controlado por el repo (ANSI, `\n`) | Sin texto libre (§2.6); el reporter sanea `path` |
| Baseline hostil que suprime todo | El baseline es entrada no confiable y se valida en el adaptador; el número de suprimidos es visible (mvp §6) |
| Baseline reescrito con un scan parcial que borra supresiones o, al revés, oculta su desaparición | Se niega con `partial-scan` (§2.5) |
| Baseline corrupto reemplazado sin revisión, con una sal nueva | Se niega con `invalid-baseline` |
| Un escáner con un bug emite un hallazgo de otra categoría, una severidad desconocida o campos extra con texto (incluido el secreto) | Validación y reconstrucción en runtime (§2.2) |
| Sal hostil en el baseline que ciega la detección de secretos | Normalización; si no es válida, baseline `invalid` (§2.5) |
| Colisión de ids por concatenación ambigua | Codificación canónica en un array JSON (§2.3) |
| Abuso de `unsafeReveal` en un paquete nuevo | Regla ESLint (§5.4, ADR 0008) y revisión del agente `security-reviewer` |

## 7. Decisiones resueltas tras la revisión

### Revisión de la rama `feat/3-core-domain` (agentes `architect` y `security-reviewer`)
Dos rondas de revisión. Corregido en la rama: validación en runtime de escáneres y
adaptadores, con lectura única de cada campo (§2.2, §2.5), `SecretValue` a prueba de
imitaciones (§2.2), `runScan` sin excepciones (§2.7), `RepoReader.describe()` (§4.2),
regla ESLint ampliada a cualquier mención y a los oráculos `hasPrefix`/`occursIn`
(ADR 0008) y desempate final por `id` en `prioritize` (mvp §2.6). **Requisitos para paquetes futuros**:
- **scanner-misconfig**: el `anchor` debe incluir el contenido que identifica el problema
  (la expresión `${{ … }}`, la imagen de `FROM`, la URL de `ADD`), no solo su posición.
  Con el mismo anchor, dos hallazgos comparten id, y suprimir uno suprimiría hallazgos
  nuevos sin que el baseline cambie en el diff del PR.
- **reporters**: sanear **todo** el texto que viene de fuera, no solo `path`: `title`,
  `vuln.url`, `osvId` y `aliases` llegan de OSV y pueden traer secuencias ANSI.

### Durante la redacción
- **Carpeta `use-cases/`** (confirmada): `runScan` llama a puertos, así que no es lógica
  pura y no encaja en `policy/`. Amplía la estructura de ADR 0001 sin contradecir su regla
  de dependencias. Ya figura en mvp §4.4–§4.5.
- **Enmienda a mvp §4.3** (aplicada): `Warning` estructurado, `schemaVersion: 1` y
  `ScanResult.warnings`.

## 8. Verificación de punta a punta
Todavía no existen ni el CLI ni los adaptadores, así que la verificación de punta a punta
es de core completo con dobles:
1. `pnpm test packages/core` → todo en verde.
2. `pnpm typecheck && pnpm lint` → sin errores (el lint incluye los invariantes de §5.4).
3. Un test `run-scan.e2e.test.ts` monta un escenario que replica `known-repo` en memoria
   (secreto en 3 commits + árbol, `.env`, dependencia vulnerable y escáner de deps
   `incomplete`) y comprueba:
   - exit 1;
   - `JSON.stringify(result)` **igual** a un `expected.json` en memoria;
   - `updateBaseline` → se niega (deps incompleto) y devuelve exit 2;
   - con deps `complete` → `save` se llama, se repite el scan con ese baseline y da exit 0
     con todos los hallazgos `suppressed`;
   - ningún valor secreto de entrada aparece en la salida ni en el baseline guardado.
4. Añadir temporalmente `import "node:fs"` o una llamada a `unsafeReveal()` en un fichero
   de core no permitido → `pnpm lint` falla.
