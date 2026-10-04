# Spec — RepoGuard MVP

Estado: borrador para revisión · Fecha: 2026-10-04

> Este spec **sustituye** a la planificación de `docs/planning/` (commit `eaa7334`),
> que incluía backend, Postgres, login y dashboard. Todo eso queda fuera del MVP (ver
> No-objetivos). Las decisiones marcadas **[por defecto]** no se discutieron en la
> entrevista y se tomaron con el criterio indicado; revísalas.

## 1. Problema

Un desarrollador o equipo pequeño quiere saber, antes de hacer push o en CI, si su repo
expone secretos, usa dependencias vulnerables o tiene configuraciones peligrosas. Las
herramientas existentes o son SaaS (exigen dar acceso al código) o cubren solo una de las
tres cosas. RepoGuard hace una cosa bien:

```
repoguard scan .
```

devuelve en segundos una lista **priorizada** de problemas, en formato legible, JSON o
SARIF, sin que el código salga de la máquina.

## 2. Alcance

### 2.1 Secretos expuestos
- Detección **solo por regex específicas** de formatos con estructura reconocible
  (prefijos tipo `AKIA`, `ghp_`, `github_pat_`, `sk_live_`, `xox[bp]-`, cabeceras PEM de
  clave privada, etc.). La entropía se usa solo como **filtro** dentro de una regla
  (descartar coincidencias de baja entropía, p. ej. un prefijo válido seguido de `X`
  repetidas), nunca como detector genérico. *Por qué: la métrica "cero falsos positivos"
  no es compatible con detectores genéricos.*
- Requisito de cada regla: el secreto capturado debe tener ≥128 bits de entropía teórica
  (en eso se apoya la seguridad del fingerprint, §7).
- Pre-filtro por keywords (estilo Gitleaks) antes de ejecutar la regex.
- Ámbitos:
  - **Árbol de trabajo**: `git ls-files -co --exclude-standard` (ficheros versionados +
    no versionados que no estén ignorados). *Por qué: un fichero nuevo sin `git add` es justo
    lo que se va a colar en el siguiente push; uno ignorado no.*
  - **Historial**: todos los blobs alcanzables desde todas las refs, **incremental** (§2.4).
- **Deduplicación**: un secreto es un único hallazgo, identificado por su fingerprint. Se
  reporta la primera aparición (commit, ruta, línea) más `inWorkingTree: boolean` y
  `occurrences: number`. La severidad **no baja** si solo está en el historial: el secreto
  está filtrado igualmente y hay que rotarlo.

### 2.2 Dependencias vulnerables
- Lockfiles soportados: `package-lock.json` (v2/v3), `pnpm-lock.yaml` (v6–v9),
  `requirements.txt`. Se buscan en todo el árbol de trabajo (monorepos), no en el historial.
- `requirements.txt`: solo se consultan las líneas `pkg==x.y.z`. Rangos, `-e`, URLs y
  `git+` se cuentan y se emiten como **aviso** ("N dependencias sin fijar, no
  verificadas"), no como hallazgos. `-r otro.txt` se sigue solo si la ruta resuelta queda
  dentro del repo.
- Consulta a OSV mediante `POST https://api.osv.dev/v1/querybatch`, enviando **solo**
  `{ecosystem, name, version}`. Lotes de ≤1000 consultas, timeout total de 5 s y 1
  reintento.
- **Si falla OSV**: se muestra un aviso visible, la categoría queda marcada
  `status: "incomplete"` y el exit code es 2 (§4.2). `--offline` salta OSV y marca la
  categoría `skipped`.
- Severidad **[por defecto]**: CVSS v3 de OSV → critical ≥9.0, high ≥7.0, medium ≥4.0,
  low <4.0. Sin puntuación: se usa `database_specific.severity` si existe y, si no,
  `medium`. *Por qué: tratar lo desconocido como low escondería vulnerabilidades reales.*

### 2.3 Misconfiguraciones (reglas iniciales [por defecto])
| id | Fichero | Regla | Severidad |
|---|---|---|---|
| `env-file-committed` | `.env`, `.env.*` versionados | excepto `*.example`, `*.sample`, `*.template` | high |
| `gha-write-all` | `.github/workflows/*.yml` | `permissions: write-all` o ausencia de `permissions` a nivel de workflow | medium |
| `gha-prt-checkout` | ídem | `pull_request_target` + checkout de `github.event.pull_request.head.*` | critical |
| `gha-script-injection` | ídem | `${{ github.event.* }}` con datos controlables (title, body, head_ref…) dentro de `run:` | high |
| `docker-root-user` | `Dockerfile*` | ninguna instrucción `USER` o último `USER` = root/0 | medium |
| `docker-latest-tag` | ídem | `FROM imagen` sin tag o con `:latest` | low |
| `docker-add-url` | ídem | `ADD http(s)://…` | medium |

Los secretos dentro de `ENV`/`ARG` los detecta el escáner de secretos; aquí no se duplican.

### 2.4 Caché incremental del historial
- SQLite en `${XDG_CACHE_HOME:-~/.cache}/repoguard/<sha256(ruta-absoluta-real)>.db`.
  **Nunca** dentro del repo. *Por qué: un repo malicioso no puede traer una caché
  preparada que marque blobs como "ya vistos" para ocultar secretos.*
- Contenido: `blob_oid → [{ruleId, line, colStart, colEnd}]` y el conjunto de commits ya
  recorridos. **No guarda ningún material derivado del secreto** (ni valor, ni hash, ni
  fragmento). Para el fingerprint de un hallazgo cacheado se vuelve a leer ese blob con
  `git cat-file` y se calcula en memoria.
- La clave de la caché incluye `rulesetVersion` (hash de las reglas compiladas). Si cambian
  las reglas, se invalida la caché completa.
- Si la caché está corrupta o tiene un esquema desconocido, se borra, se avisa y se hace un
  escaneo completo. Nunca falla el scan por la caché.

### 2.5 Supresión: baseline
- `repoguard scan --update-baseline` escribe `.repoguard-baseline.json` (pensado para
  commitearse):
  ```json
  { "version": 1, "salt": "<32 bytes hex aleatorios>",
    "entries": [{ "fingerprint": "<hex>", "ruleId": "aws-access-key", "note": "" }] }
  ```
- Los hallazgos presentes en el baseline se reportan como `suppressed: true`, **no
  cuentan** para el exit code y en la salida legible se resumen en una línea.
- El baseline es entrada **no confiable** (viene del repo): se valida con esquema y, si es
  inválido, se avisa y se ignora entero. Nunca se ignora parcialmente en silencio.

### 2.6 Priorización
Orden **[por defecto]**: severidad desc → categoría (secret > dependency > misconfig) →
`inWorkingTree` primero → ruta → línea → `id`. *Por qué: a igual severidad, un secreto exige
rotarlo ya, mientras que una dependencia se arregla con un upgrade.* El `id` final
desempata hallazgos sin línea en el mismo fichero (p. ej. dos vulnerabilidades del mismo
lockfile), para que el orden no dependa del orden de emisión. Las rutas y el `id` se
comparan por código, como git, no según el idioma del sistema.

### 2.7 GitHub Action
- `action.yml` composite: `setup-node` → `npx repoguard@<versión fijada> scan . --format sarif
  --output repoguard.sarif --fail-on <input>` → `github/codeql-action/upload-sarif`
  (con `if: always()`, para que el SARIF se suba aunque el scan falle).
- Documentar `actions/checkout` con `fetch-depth: 0`. Si el clon es superficial
  (`git rev-parse --is-shallow-repository`), se avisa de "historial incompleto" y se escanea
  lo que haya.
- La caché se puede persistir entre runs con `actions/cache` sobre `~/.cache/repoguard`.

## 3. No-objetivos
- SaaS multiusuario, backend, dashboard, cuentas y OAuth a repos de terceros (rompen el
  modelo de confianza local-first). Sustituye a `docs/planning/03–05`.
- SAST completo (para eso existen Semgrep y CodeQL).
- Arreglo automático: el MVP informa y **nunca modifica** ficheros del repo, salvo el
  baseline cuando se pide explícitamente con `--update-baseline`.
- Verificación en vivo de secretos contra APIs de proveedores (sería red adicional).
- Detección genérica por entropía y reglas definidas por el usuario.
- Ecosistemas que no sean npm/pnpm/pip; `package.json` sin lockfile.
- Comentarios inline de supresión (con el baseline basta para el MVP).

## 4. Interfaces

### 4.1 CLI
```
repoguard scan [ruta=.]
  --format text|json|sarif     (por defecto: text si stdout es TTY, si no json)
  --output <fichero>           (por defecto: stdout)
  --fail-on critical|high|medium|low|none   (por defecto: high)
  --offline                    no consulta OSV
  --no-history                 solo árbol de trabajo
  --no-cache                   ignora y no escribe la caché
  --update-baseline            escribe .repoguard-baseline.json con los hallazgos actuales
```
- Los avisos y el progreso van a **stderr**. stdout solo contiene el informe, para que
  `| jq` funcione siempre.
- `ruta` debe ser un repo git (o estar dentro de uno). Si no lo es, exit 2 con un mensaje
  claro.

### 4.2 Exit codes
| Código | Significado |
|---|---|
| 0 | Sin hallazgos no suprimidos con severidad ≥ `--fail-on` |
| 1 | Hay hallazgos no suprimidos con severidad ≥ `--fail-on` |
| 2 | Error de ejecución **o** scan incompleto (OSV caído, git ausente, ruta inválida) |

Si hay hallazgos ≥ umbral **y** el scan está incompleto, gana **1**. *Por qué: lo
importante para el gate es que ya se sabe que el repo es inseguro.*

### 4.3 Modelo de dominio (packages/core)
```ts
type Severity = "critical" | "high" | "medium" | "low";
type Category = "secret" | "dependency" | "misconfig";

interface Finding {
  id: string;                 // fingerprint (secret) o hash estable sin nº de línea (ver finding-runscan.md §2.3)
  category: Category;
  ruleId: string;
  severity: Severity;
  title: string;
  location:
    | { kind: "file"; path: string; line?: number; column?: number; commit?: string }
    | { kind: "package"; lockfile: string; ecosystem: string; name: string; version: string };
  secret?: { redacted: string; length: number; inWorkingTree: boolean; occurrences: number };
  vuln?: { osvId: string; aliases: string[]; fixedIn?: string; url: string };
  suppressed: boolean;
}

type WarningCode =
  | "SCANNER_FAILED" | "SCANNER_CONTRACT_VIOLATION"
  | "FILE_TOO_LARGE" | "BINARY_SKIPPED" | "LINE_TRUNCATED"
  | "UNPINNED_DEPENDENCIES" | "LOCKFILE_INVALID" | "REQUIREMENTS_ESCAPE"
  | "OSV_UNAVAILABLE" | "SHALLOW_CLONE" | "CACHE_RESET"
  | "BASELINE_INVALID" | "BASELINE_UPDATE_REFUSED" | "BASELINE_SAVE_FAILED";

interface Warning {          // sin campos de texto libre
  code: WarningCode;
  path?: string;             // saneada por el reporter
  count?: number;
  reason?: "partial-scan" | "invalid-baseline";
}

interface ScanResult {
  schemaVersion: 1;
  tool: { name: "repoguard"; version: string; rulesetVersion: string };
  target: { root: string; headCommit?: string; shallow: boolean };
  categories: Record<Category, { status: "complete" | "incomplete" | "skipped"; warnings: Warning[] }>;
  warnings: Warning[];       // globales: caché, baseline, clon superficial
  findings: Finding[];       // ya ordenados (§2.6)
  durationMs: number;
}
```
`ScanResult` en JSON es el **contrato estable** (`schemaVersion: 1`). El SARIF se
genera a partir de él. Los avisos son **estructurados** (código de un conjunto cerrado,
sin texto libre) y el texto lo genera el reporter. *Por qué: así es imposible por
construcción que un aviso contenga el contenido de una línea, y las rutas hostiles se
sanean en un único sitio.* Detalle en [finding-runscan.md](finding-runscan.md).

### 4.4 Puertos (packages/core/src/ports)
| Puerto | Responsabilidad | Adaptador MVP |
|---|---|---|
| `RepoReader` | listar ficheros del árbol, iterar blobs del historial desde N commits, leer blob por oid, detectar si el clon es superficial | git vía `execFile` |
| `Scanner` | `scan(ctx) → AsyncIterable<Finding \| Warning>` | secrets, deps, misconfig |
| `VulnerabilityDb` | `queryBatch(pkgs) → Vuln[]` | cliente OSV |
| `ScanCache` | coincidencias por blob y commits vistos | SQLite |
| `BaselineStore` | cargar/guardar el baseline | fichero JSON |
| `Reporter` | `render(ScanResult) → string` | text, json, sarif |

La lógica pura vive en `core/src/policy`: `prioritize`, `dedupeSecrets`, `applyBaseline`,
`exitCode`, `redact`, `fingerprint` (recibe el hash como función inyectada, porque core no
importa `node:crypto`). La orquestación (`runScan`) vive en `core/src/use-cases`: llama a
puertos, así que no es lógica pura, pero sigue sin hacer E/S directa.

### 4.5 Ficheros afectados (todos nuevos; propuesta de layout)
```
packages/core/src/{domain,ports,policy}/…     modelo, puertos y lógica pura
packages/core/src/use-cases/…                 orquestación (runScan)
packages/scanner-secrets/                     reglas + motor regex
packages/scanner-deps/                        parsers de lockfiles
packages/scanner-misconfig/                   reglas Dockerfile / GHA / .env
packages/adapter-git/                         RepoReader (execFile, cat-file --batch)
packages/adapter-osv/                         VulnerabilityDb
packages/adapter-sqlite/                      ScanCache
packages/reporters/                           text, json, sarif
packages/cli/                                 composición (inyección de dependencias) + argumentos
action.yml                                    GitHub Action composite
fixtures/known-repo/build.sh                  genera el repo de prueba (§5.4)
fixtures/known-repo/expected.json             hallazgos esperados exactos
docs/adr/0001…000N                            ADRs de las decisiones de §8
```

## 5. Casos de test

### 5.1 Unitarios (core, sin E/S)
- `prioritize`: el orden de §2.6 se cumple con empates en cada nivel.
- `exitCode`: tabla completa con umbral × hallazgos × suprimidos × estado incompleto
  (incluido "hallazgo ≥ umbral + incompleto = 1").
- `dedupeSecrets`: el mismo secreto en 3 commits y en el árbol da 1 hallazgo con
  `occurrences=4`, `inWorkingTree=true` y la primera aparición como ubicación.
- `redact`: el resultado nunca contiene caracteres posteriores al prefijo de la regla
  (property test con secretos aleatorios).
- `applyBaseline`: suprime por fingerprint; un baseline inválido no suprime nada y genera
  un aviso.

### 5.2 Escáneres
- Secrets: cada regla tiene un caso positivo y casos negativos (placeholder de `X`
  repetidas, baja entropía, prefijo dentro de una palabra más larga).
- **ReDoS**: cada regex procesa una línea de 1 MB de caracteres adversarios en <50 ms.
- Ficheros >1 MiB o con un byte NUL en los primeros 8 KiB se omiten y se cuentan en un
  aviso **[por defecto]**.
- Líneas >64 KiB se truncan para el matching **[por defecto]**.
- Deps: `package-lock` v2 y v3, `pnpm-lock` v6 y v9, requirements con `==`, rangos, `-e`,
  `-r` que escapa del repo (`-r ../../etc/x`, se rechaza) y un lockfile corrupto (aviso,
  no crash).
- Misconfig: un positivo y un negativo por regla; `.env.example` no dispara.

### 5.3 Adaptadores
- git: rutas con espacios, comillas, `$()`, un `-` inicial y saltos de línea en el nombre
  no causan inyección ni rompen el parseo (`-z` en todos los comandos).
- git: un symlink que apunta fuera del repo no se sigue; se escanea el blob (el texto del
  enlace), no el destino.
- git: un repo sin commits, un HEAD detached y un clon superficial (aviso).
- OSV: respuesta OK, timeout, 5xx, JSON malformado o con campos de tipo inesperado (todo
  validado con esquema) y lotes >1000.
- SQLite: caché corrupta → se reconstruye; un cambio de `rulesetVersion` → se invalida.
- Incremental: el 2.º scan tras un commit nuevo solo lee los blobs nuevos y da exactamente
  los mismos hallazgos que un scan con `--no-cache`.

### 5.4 Repo de prueba conocido (métrica "cero FP")
`fixtures/known-repo/build.sh` crea un repo git temporal con un historial determinista
(autor y fechas fijos): secretos falsos añadidos y luego borrados, `.env` versionado, un
workflow vulnerable, un Dockerfile sin `USER`, lockfiles con una versión vulnerable
conocida y **señuelos** (UUIDs, hashes SHA, base64 de imágenes, `.env.example`,
placeholders). El test compara la salida JSON con `expected.json` **por igualdad
exacta**: un hallazgo de más es un FP y hace fallar el test. *Por qué un script: no se
puede commitear un `.git` anidado.*

### 5.5 Reporters
- El JSON valida contra el esquema de `ScanResult`.
- El SARIF valida contra el esquema SARIF 2.1.0 oficial y GitHub lo acepta (verificación
  E2E).
- **Test de no-filtrado**: se ejecuta el scan sobre `known-repo` y se comprueba con grep
  que ningún valor secreto completo de los fixtures aparece en stdout, stderr, el JSON, el
  SARIF, el baseline ni el `.db` de la caché.

### 5.6 Rendimiento
- Benchmark sobre un repo público mediano fijado por commit **[por defecto]**: ~5.000
  ficheros y ~10.000 commits, con `--offline`.
  - Scan **con caché caliente**: <10 s (métrica del MVP).
  - Primer scan en frío: se mide y se reporta (objetivo orientativo <60 s), sin bloquear.
    *Por qué: con historial completo, los 10 s solo son alcanzables de forma incremental;
    así lo acordamos.*

## 6. Riesgos de seguridad
El repo escaneado es **entrada no confiable**: cualquier fichero, nombre de ruta,
lockfile, baseline o config de git puede ser hostil.

| Riesgo | Mitigación |
|---|---|
| Secreto sin redactar en la salida, logs, caché o baseline | Redacción en el dominio antes de cualquier reporter; la caché no guarda material del secreto; test de no-filtrado (§5.5); los errores nunca incluyen el contenido de la línea |
| Inyección de comandos al invocar git | `execFile`/`spawn` sin shell, argumentos en array, `--` antes de las rutas, `-z` |
| Config de git maliciosa del repo (`core.fsmonitor`, `core.pager`, filtros, hooks) que ejecuta código | Invocar git con `-c core.fsmonitor= -c core.hooksPath=/dev/null --no-pager`, sin comandos que ejecuten filtros (usar `cat-file`/`ls-files`/`rev-list`, nunca `checkout`) y `GIT_CONFIG_NOSYSTEM=1` **[por defecto]** |
| Path traversal / symlinks fuera del repo | Leer contenido vía objetos git y no vía el sistema de ficheros siempre que se pueda; para los no versionados, `realpath` dentro de la raíz y sin seguir symlinks; `-r` de requirements confinado |
| ReDoS | Regex sin cuantificadores anidados, test adversario por regla, límite de longitud de línea |
| Agotar memoria (blobs enormes, lockfiles gigantes, YAML bomb) | Límite de tamaño por fichero, streaming de `cat-file --batch`, parser YAML con alias deshabilitados o limitados |
| Respuesta OSV manipulada o malformada | Validación de esquema; las URLs de OSV se muestran como texto y nunca se abren; los campos se escapan en la salida de terminal (sin secuencias ANSI) |
| Secuencias de escape ANSI en nombres de fichero hostiles | Sanear las rutas en el reporter de texto |
| Caché envenenada | Vive fuera del repo (§2.4) |
| Baseline que suprime todo | Es un fichero visible en el diff del PR; el resumen muestra el número de suprimidos |
| Fuerza bruta del fingerprint | SHA-256 con sal por repo sobre secretos de ≥128 bits |
| Fuga de metadatos a OSV | Solo se envía nombre+versión+ecosistema; documentado; `--offline` disponible |

## 7. Fingerprint y redacción
- `fingerprint = hex(SHA-256(salt ‖ 0x00 ‖ ruleId ‖ 0x00 ‖ secreto))`, con `salt` tomada
  del baseline. Si no hay baseline, la sal es aleatoria en cada ejecución (solo sirve para
  deduplicar dentro del scan).
- `redacted = <prefijo público de la regla> + "****"` y `length` aparte. Ejemplo:
  `ghp_**** (40 chars)`. Las reglas sin prefijo (PEM) muestran solo el tipo:
  `[private key, RSA]`.

## 8. Decisiones a registrar como ADR
`docs/adr/` está vacío. Antes de implementar conviene crear un ADR para cada una:
1. Solo CLI + Action; backend y dashboard descartados (supera `docs/planning`).
2. Git mediante el binario y `execFile`, no una librería JS.
3. Caché incremental SQLite fuera del repo y sin material de secretos.
4. Detección solo por regex específicas; sin entropía genérica.
5. Baseline con fingerprint SHA-256 con sal como único mecanismo de supresión.
6. Exit codes 0/1/2 con `--fail-on`, donde "incompleto" es 2.

## 9. Verificación de punta a punta
1. `pnpm build && fixtures/known-repo/build.sh /tmp/rg-known` (el script imprime la ruta).
2. `repoguard scan /tmp/rg-known --format json --offline > out.json; echo $?`
   → exit **1**. `out.json` es igual a `expected.json` sin la categoría deps
   (`status: "skipped"`).
3. Repetir sin `--offline` → aparece la vulnerabilidad conocida del lockfile, exit 1.
   Con la red cortada → aviso en stderr, deps `incomplete` y exit 1, porque ya hay
   secretos ≥ high.
4. `repoguard scan /tmp/rg-known --update-baseline`, después `repoguard scan /tmp/rg-known`
   → exit **0**, con el resumen "N suprimidos".
5. Añadir un commit con un secreto falso nuevo → el scan detecta solo ese, exit 1 y lee
   solo los blobs nuevos (comprobable con `--verbose` en stderr).
6. Test de no-filtrado: `grep -rF -f fixtures/known-repo/secrets.txt out.json repoguard.sarif
   .repoguard-baseline.json ~/.cache/repoguard/` → **sin coincidencias**.
7. Benchmark (§5.6) con caché caliente: <10 s.
8. En un repo propio en GitHub: añadir la Action con `fetch-depth: 0`, abrir un PR con un
   secreto falso y comprobar que el job falla, que el SARIF se sube y que la alerta aparece
   en *Security → Code scanning* con el valor redactado.
