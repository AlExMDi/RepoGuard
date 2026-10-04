import { SEVERITIES, type Category, type FindingLocation, type Severity } from "../domain/finding";
import type { RawSecretMatch } from "../domain/raw-secret-match";
import { SecretValue } from "../domain/secret-value";
import { WARNING_CODES, WARNING_REASONS, type Warning } from "../domain/warning";
import type { FindingDraft } from "../ports/scanner";

// Validación en runtime de lo que envían los escáneres (spec finding-runscan §2.2).
// Los tipos de TypeScript solo existen al compilar: un escáner con un bug puede enviar
// cualquier cosa. Cada función reconstruye el objeto campo a campo (lista blanca) y
// devuelve null si algo no encaja; runScan lo trata como SCANNER_CONTRACT_VIOLATION.

/** Ids de regla de RepoGuard y de OSV (GHSA-…, CVE-…, PYSEC-…): sin espacios ni control. */
const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/** Reglas de secretos: solo nuestras constantes, en kebab-case. Sin NUL (entra en el hash). */
const SECRET_RULE_ID = /^[a-z0-9]+(-[a-z0-9]+)*$/;
/** Un prefijo público largo dejaría ver parte del secreto en `redacted`. */
const MAX_PUBLIC_PREFIX = 12;

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const isPosInt = (v: unknown): v is number => Number.isInteger(v) && (v as number) >= 1;
const isOneOf = <T extends string>(list: readonly T[], v: unknown): v is T =>
  isStr(v) && (list as readonly string[]).includes(v);

/** `undefined` si el campo no está; null si está y no es válido. */
function optional<T>(v: unknown, ok: (x: unknown) => x is T): T | undefined | null {
  if (v === undefined) return undefined;
  return ok(v) ? v : null;
}

export function sanitizeWarning(input: unknown): Warning | null {
  if (!isObj(input) || !isOneOf(WARNING_CODES, input.code)) return null;
  const path = optional(input.path, isStr);
  const count = optional(
    input.count,
    (v): v is number => Number.isInteger(v) && (v as number) >= 0,
  );
  const reason = optional(input.reason, (v): v is Warning["reason"] & string =>
    isOneOf(WARNING_REASONS, v),
  );
  if (path === null || count === null || reason === null) return null;
  return {
    code: input.code,
    ...(path !== undefined && { path }),
    ...(count !== undefined && { count }),
    ...(reason !== undefined && { reason }),
  };
}

function sanitizeFileLocation(loc: Obj): Extract<FindingLocation, { kind: "file" }> | null {
  if (!isStr(loc.path)) return null;
  const line = optional(loc.line, isPosInt);
  const column = optional(loc.column, isPosInt);
  const commit = optional(loc.commit, isStr);
  if (line === null || column === null || commit === null) return null;
  return {
    kind: "file",
    path: loc.path,
    ...(line !== undefined && { line }),
    ...(column !== undefined && { column }),
    ...(commit !== undefined && { commit }),
  };
}

function sanitizeLocation(loc: unknown): FindingLocation | null {
  if (!isObj(loc)) return null;
  if (loc.kind === "file") return sanitizeFileLocation(loc);
  if (loc.kind === "package") {
    const { lockfile, ecosystem, name, version } = loc;
    if (!isStr(lockfile) || !isStr(ecosystem) || !isStr(name) || !isStr(version)) return null;
    return { kind: "package", lockfile, ecosystem, name, version };
  }
  return null;
}

function sanitizeVuln(v: unknown): FindingDraft["vuln"] | null {
  if (!isObj(v) || !isStr(v.osvId) || !isStr(v.url)) return null;
  if (!Array.isArray(v.aliases) || !v.aliases.every(isStr)) return null;
  const fixedIn = optional(v.fixedIn, isStr);
  if (fixedIn === null) return null;
  return {
    osvId: v.osvId,
    aliases: [...v.aliases],
    url: v.url,
    ...(fixedIn !== undefined && { fixedIn }),
  };
}

/**
 * Borrador de deps o misconfig. Nunca lleva `secret`: los secretos llegan solo como
 * RawSecretMatch. `expected` es la categoría del escáner que lo emitió.
 */
export function sanitizeFindingDraft(input: unknown, expected: Category): FindingDraft | null {
  if (!isObj(input) || input.category !== expected || expected === "secret") return null;
  const { ruleId, severity, title } = input;
  if (!isStr(ruleId) || !RULE_ID.test(ruleId)) return null;
  if (!isOneOf<Severity>(SEVERITIES, severity) || !isStr(title)) return null;

  const location = sanitizeLocation(input.location);
  if (location === null) return null;
  const base = { category: expected, ruleId, severity, title, location };

  if (expected === "dependency") {
    const vuln = sanitizeVuln(input.vuln);
    return location.kind === "package" && vuln ? { ...base, vuln } : null;
  }
  return location.kind === "file" ? base : null;
}

export function sanitizeSecretMatch(input: unknown): RawSecretMatch | null {
  if (!isObj(input) || !(input.value instanceof SecretValue)) return null;
  const { ruleId, severity, title, publicPrefix, kindLabel, value, inWorkingTree, ordinal } = input;
  if (!isStr(ruleId) || !SECRET_RULE_ID.test(ruleId)) return null;
  if (!isOneOf<Severity>(SEVERITIES, severity) || !isStr(title) || !isStr(kindLabel)) return null;
  if (typeof inWorkingTree !== "boolean" || !Number.isFinite(ordinal)) return null;
  if (publicPrefix !== null) {
    if (!isStr(publicPrefix) || publicPrefix.length > MAX_PUBLIC_PREFIX) return null;
    if (!value.hasPrefix(publicPrefix)) return null;
  }

  if (!isObj(input.location)) return null;
  const loc = sanitizeFileLocation(input.location);
  if (!loc || loc.line === undefined || loc.column === undefined) return null;
  return {
    ruleId,
    severity,
    title,
    publicPrefix,
    kindLabel,
    value,
    location: {
      path: loc.path,
      line: loc.line,
      column: loc.column,
      ...(loc.commit !== undefined && { commit: loc.commit }),
    },
    inWorkingTree,
    ordinal: ordinal as number,
  };
}
