import { SEVERITIES, type Category, type FindingLocation, type Severity } from "../domain/finding";
import type { RawSecretMatch } from "../domain/raw-secret-match";
import { SecretValue } from "../domain/secret-value";
import { WARNING_CODES, WARNING_REASONS, type Warning } from "../domain/warning";
import type { FindingDraft } from "../ports/scanner";

// Validación en runtime de lo que envían los escáneres (spec finding-runscan §2.2).
// Los tipos de TypeScript solo existen al compilar: un escáner con un bug puede enviar
// cualquier cosa. Cada función reconstruye el objeto campo a campo (lista blanca) y
// devuelve null si algo no encaja; runScan lo trata como SCANNER_CONTRACT_VIOLATION.
//
// Regla de oro: cada campo se lee UNA vez (desestructurando) y se valida y copia esa
// variable local. Leerlo dos veces permitiría que un getter devolviera un valor válido al
// validar y otro distinto al copiar (TOCTOU).

/** Ids de regla de RepoGuard y de OSV (GHSA-…, CVE-…, PYSEC-…): sin espacios ni control. */
const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/** Reglas de secretos: solo nuestras constantes, en kebab-case. Sin NUL (entra en el hash). */
const SECRET_RULE_ID = /^[a-z0-9]+(-[a-z0-9]+)*$/;
/** Un prefijo público largo dejaría ver parte del secreto en `redacted`. */
const MAX_PUBLIC_PREFIX = 12;
/** Caracteres que deben quedar ocultos tras el prefijo: con menos, el fingerprint del baseline commiteado se podría romper por fuerza bruta. */
const MIN_HIDDEN_CHARS = 16;
const MAX_ALIASES = 100;
const MAX_TITLE = 512;
const MAX_LABEL = 64;
/** Rutas, URLs, nombres y versiones. */
const MAX_FIELD = 4096;

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const strMax =
  (max: number) =>
  (v: unknown): v is string =>
    isStr(v) && v.length <= max;
const isField = strMax(MAX_FIELD);
const isTitle = strMax(MAX_TITLE);
const isLabel = strMax(MAX_LABEL);
const isRuleId = (v: unknown): v is string => isStr(v) && RULE_ID.test(v);
const isPosInt = (v: unknown): v is number => Number.isInteger(v) && (v as number) >= 1;
const isCount = (v: unknown): v is number => Number.isInteger(v) && (v as number) >= 0;
const isOneOf = <T extends string>(list: readonly T[], v: unknown): v is T =>
  isStr(v) && (list as readonly string[]).includes(v);

/** `undefined` si el campo no está; null si está y no es válido. */
function optional<T>(v: unknown, ok: (x: unknown) => x is T): T | undefined | null {
  if (v === undefined) return undefined;
  return ok(v) ? v : null;
}

export function sanitizeWarning(input: unknown): Warning | null {
  if (!isObj(input)) return null;
  const { code: rawCode, path: rawPath, count: rawCount, reason: rawReason } = input;
  if (!isOneOf(WARNING_CODES, rawCode)) return null;
  const path = optional(rawPath, isField);
  const count = optional(rawCount, isCount);
  const reason = optional(rawReason, (v): v is NonNullable<Warning["reason"]> =>
    isOneOf(WARNING_REASONS, v),
  );
  if (path === null || count === null || reason === null) return null;
  return {
    code: rawCode,
    ...(path !== undefined && { path }),
    ...(count !== undefined && { count }),
    ...(reason !== undefined && { reason }),
  };
}

function sanitizeFileLocation(input: Obj): Extract<FindingLocation, { kind: "file" }> | null {
  const { path, line: rawLine, column: rawColumn, commit: rawCommit } = input;
  if (!isField(path)) return null;
  const line = optional(rawLine, isPosInt);
  const column = optional(rawColumn, isPosInt);
  const commit = optional(rawCommit, isField);
  if (line === null || column === null || commit === null) return null;
  return {
    kind: "file",
    path,
    ...(line !== undefined && { line }),
    ...(column !== undefined && { column }),
    ...(commit !== undefined && { commit }),
  };
}

function sanitizeLocation(input: unknown): FindingLocation | null {
  if (!isObj(input)) return null;
  const { kind } = input;
  if (kind === "file") return sanitizeFileLocation(input);
  if (kind === "package") {
    const { lockfile, ecosystem, name, version } = input;
    if (!isField(lockfile) || !isField(ecosystem) || !isField(name) || !isField(version)) {
      return null;
    }
    return { kind: "package", lockfile, ecosystem, name, version };
  }
  return null;
}

/**
 * Copia acotada de un array no confiable: lee `length` una vez, rechaza antes de recorrer
 * si es enorme (un array disperso de millones de huecos agotaría la memoria) y lee cada
 * posición una sola vez. Los huecos quedan como `undefined` y no pasan la validación.
 */
function boundedCopy(input: unknown, max: number): unknown[] | null {
  if (!Array.isArray(input)) return null;
  const n: unknown = input.length;
  if (!Number.isInteger(n) || (n as number) > max) return null;
  return Array.from({ length: n as number }, (_, i) => input[i] as unknown);
}

function sanitizeVuln(input: unknown): FindingDraft["vuln"] | null {
  if (!isObj(input)) return null;
  const { osvId, url, aliases: rawAliases, fixedIn: rawFixedIn } = input;
  if (!isRuleId(osvId) || !isField(url)) return null;
  const aliases = boundedCopy(rawAliases, MAX_ALIASES);
  if (aliases === null || !aliases.every(isRuleId)) return null;
  const fixedIn = optional(rawFixedIn, isField);
  if (fixedIn === null) return null;
  return {
    osvId,
    aliases: aliases as string[],
    url,
    ...(fixedIn !== undefined && { fixedIn }),
  };
}

/**
 * Borrador de deps o misconfig. Nunca lleva `secret`: los secretos llegan solo como
 * RawSecretMatch. `expected` es la categoría del escáner que lo emitió.
 */
export function sanitizeFindingDraft(input: unknown, expected: Category): FindingDraft | null {
  if (!isObj(input) || expected === "secret") return null;
  const { category, ruleId, severity, title, location: rawLocation, vuln: rawVuln } = input;
  if (category !== expected || !isRuleId(ruleId)) return null;
  if (!isOneOf<Severity>(SEVERITIES, severity) || !isTitle(title)) return null;

  const location = sanitizeLocation(rawLocation);
  if (location === null) return null;
  const base = { category: expected, ruleId, severity, title, location };

  if (expected === "dependency") {
    const vuln = sanitizeVuln(rawVuln);
    return location.kind === "package" && vuln ? { ...base, vuln } : null;
  }
  return location.kind === "file" ? base : null;
}

export function sanitizeSecretMatch(input: unknown): RawSecretMatch | null {
  if (!isObj(input)) return null;
  const {
    ruleId,
    severity,
    title,
    publicPrefix,
    kindLabel,
    value,
    location: rawLocation,
    inWorkingTree,
    ordinal,
  } = input;
  if (!SecretValue.isGenuine(value)) return null;
  if (!isStr(ruleId) || !SECRET_RULE_ID.test(ruleId)) return null;
  if (!isOneOf<Severity>(SEVERITIES, severity) || !isTitle(title) || !isLabel(kindLabel)) {
    return null;
  }
  if (typeof inWorkingTree !== "boolean" || typeof ordinal !== "number") return null;
  if (!Number.isFinite(ordinal)) return null;

  let prefixLength = 0;
  if (publicPrefix !== null) {
    if (!isStr(publicPrefix) || publicPrefix.length > MAX_PUBLIC_PREFIX) return null;
    if (!SecretValue.hasPrefix(value, publicPrefix)) return null;
    prefixLength = publicPrefix.length;
  }
  if (SecretValue.lengthOf(value) - prefixLength < MIN_HIDDEN_CHARS) return null;

  if (!isObj(rawLocation)) return null;
  const location = sanitizeFileLocation(rawLocation);
  if (!location || location.line === undefined || location.column === undefined) return null;

  // Ningún texto que acabe en la salida puede contener el secreto completo (p. ej. un bug
  // que meta la línea analizada en kindLabel).
  const texts = [ruleId, title, kindLabel, location.path, location.commit ?? ""];
  if (texts.some((text) => SecretValue.occursIn(value, text))) return null;

  return {
    ruleId,
    severity,
    title,
    publicPrefix,
    kindLabel,
    value,
    location: {
      path: location.path,
      line: location.line,
      column: location.column,
      ...(location.commit !== undefined && { commit: location.commit }),
    },
    inWorkingTree,
    ordinal,
  };
}
