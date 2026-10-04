import type { BaselineEntry } from "../domain/baseline";
import type { BaselineLoad } from "../ports/baseline-store";
import type { RepoDescription, RepoFatalCode } from "../ports/repo-reader";
import { normalizeSalt } from "./fingerprint";
import { boundedCopy, isField, isObj, isOneOf, isStr, optional, strMax } from "./guards";

// Validación en runtime de lo que devuelven los adaptadores (spec finding-runscan §2.5, §2.7).
// El baseline viene del repo escaneado: es entrada no confiable aunque el adaptador lo
// valide con esquema. Como en sanitize-event, cada campo se lee una vez y se reconstruye.

/** SHA-256 en hex (spec mvp §7). */
const FINGERPRINT = /^[0-9a-f]{64}$/;
const MAX_ENTRIES = 100_000;
const MAX_NOTE = 4096;
const isNote = strMax(MAX_NOTE);
const FATAL_CODES: readonly RepoFatalCode[] = ["NOT_A_GIT_REPO", "GIT_MISSING", "REPO_ERROR"];
const INVALID: BaselineLoad = { kind: "invalid" };
const REPO_ERROR: RepoDescription = { kind: "fatal", code: "REPO_ERROR" };

function sanitizeEntry(input: unknown): BaselineEntry | null {
  if (!isObj(input)) return null;
  const { fingerprint, ruleId, note } = input;
  if (!isStr(fingerprint) || !isField(ruleId) || !isNote(note)) return null;
  // En mayúsculas sigue siendo el mismo hash: se normaliza para no perder la nota.
  const lower = fingerprint.toLowerCase();
  return FINGERPRINT.test(lower) ? { fingerprint: lower, ruleId, note } : null;
}

/**
 * Cualquier campo inválido invalida el baseline entero: nunca se ignora a medias
 * (spec mvp §2.5). La sal y los fingerprints se normalizan a minúsculas.
 */
export function sanitizeBaselineLoad(input: unknown): BaselineLoad {
  if (!isObj(input)) return INVALID;
  const { kind, baseline } = input;
  if (kind === "missing") return { kind: "missing" };
  if (kind !== "valid" || !isObj(baseline)) return INVALID;

  const { version, salt: rawSalt, entries: rawEntries } = baseline;
  if (version !== 1 || !isStr(rawSalt)) return INVALID;
  const salt = normalizeSalt(rawSalt);
  const copied = boundedCopy(rawEntries, MAX_ENTRIES);
  if (salt === null || copied === null) return INVALID;

  const entries: BaselineEntry[] = [];
  for (const raw of copied) {
    const entry = sanitizeEntry(raw);
    if (!entry) return INVALID;
    entries.push(entry);
  }
  return { kind: "valid", baseline: { version: 1, salt, entries } };
}

/** Una forma inesperada es REPO_ERROR: sin datos del repo no se puede escanear. */
export function sanitizeRepoDescription(input: unknown): RepoDescription {
  if (!isObj(input)) return REPO_ERROR;
  const { kind, code, info } = input;
  if (kind === "fatal") return isOneOf(FATAL_CODES, code) ? { kind: "fatal", code } : REPO_ERROR;
  if (kind !== "ok" || !isObj(info)) return REPO_ERROR;

  const { root, headCommit: rawHead, shallow } = info;
  const headCommit = optional(rawHead, isField);
  if (!isField(root) || root === "" || typeof shallow !== "boolean" || headCommit === null) {
    return REPO_ERROR;
  }
  return {
    kind: "ok",
    info: { root, ...(headCommit !== undefined && { headCommit }), shallow },
  };
}
