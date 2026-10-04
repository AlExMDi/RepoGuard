import { CATEGORIES, type Category, type FailOn, type Finding } from "../domain/finding";
import { isOneOf } from "../policy/guards";
import type { CategoryReport, CategoryStatus, ScanResult } from "../domain/scan-result";
import type { Warning, WarningCode } from "../domain/warning";
import type { BaselineLoad, BaselineStore } from "../ports/baseline-store";
import type { Clock } from "../ports/clock";
import type { Hasher, RandomBytes } from "../ports/crypto";
import type { RepoDescription, RepoFatalCode, RepoReader } from "../ports/repo-reader";
import type { ScanContext, Scanner } from "../ports/scanner";
import { applyBaseline } from "../policy/apply-baseline";
import { dedupeSecrets } from "../policy/dedupe-secrets";
import { exitCode } from "../policy/exit-code";
import { findingId } from "../policy/finding-id";
import { prioritize } from "../policy/prioritize";
import { sanitizeBaselineLoad, sanitizeRepoDescription } from "../policy/sanitize-adapter";
import {
  sanitizeFindingDraft,
  sanitizeSecretMatch,
  sanitizeWarning,
} from "../policy/sanitize-event";
import { secretDraft, type SecretOccurrence } from "../policy/secret-draft";
import { updateBaseline } from "../policy/update-baseline";

export interface RunScanDeps {
  /** Solo describe(): los métodos de lectura los usan los escáneres, no runScan. */
  repo: Pick<RepoReader, "describe">;
  scanners: readonly Scanner[];
  baseline: BaselineStore;
  hash: Hasher;
  random: RandomBytes;
  clock: Clock;
}

export interface RunScanOptions {
  failOn: FailOn;
  /** false con --no-history. */
  history: boolean;
  /** Categorías que no se ejecutan (--offline → dependency). */
  skipped: readonly Category[];
  updateBaseline: boolean;
  toolVersion: string;
  rulesetVersion: string;
}

/** INVALID_SCANNER: error de cableado en cli (categoría desconocida o que no se puede leer). */
export type RunScanFatalCode = RepoFatalCode | "INVALID_SCANNER";

export type RunScanOutcome =
  | { kind: "ok"; result: ScanResult; exitCode: 0 | 1 | 2 }
  | { kind: "fatal"; code: RunScanFatalCode; exitCode: 2 };

/** Lo que produjo un escáner. Nunca contiene un SecretValue. */
interface Collected {
  category: Category;
  status: CategoryStatus;
  warnings: Warning[];
  findings: Finding[];
  secrets: SecretOccurrence[];
}

/**
 * Caso de uso principal (spec finding-runscan §2.7). No hace E/S directa: todo pasa por
 * puertos y nunca lanza: los errores de repo se devuelven como `fatal` y los de los
 * adaptadores como avisos, sin su mensaje (spec finding-runscan §2.2 y §2.7).
 */
export async function runScan(deps: RunScanDeps, opts: RunScanOptions): Promise<RunScanOutcome> {
  const started = deps.clock();

  const repo = await describeRepo(deps.repo);
  if (repo.kind === "fatal") return { kind: "fatal", code: repo.code, exitCode: 2 };

  // Lo desconocido bloquea: un escáner con una categoría mal escrita perdería su estado
  // `incomplete` en silencio y el gate podría dar 0.
  const scanners = categorize(deps.scanners);
  if (scanners === null) return { kind: "fatal", code: "INVALID_SCANNER", exitCode: 2 };

  const warnings: Warning[] = [];
  if (repo.info.shallow) warnings.push({ code: "SHALLOW_CLONE" });

  const load = await loadBaseline(deps.baseline);
  if (load.kind === "invalid") warnings.push({ code: "BASELINE_INVALID" });
  const salt = load.kind === "valid" ? load.baseline.salt : toHex(deps.random(32));

  const ctx: ScanContext = { repo: repo.info, history: opts.history };
  const active = scanners.filter((s) => !opts.skipped.includes(s.category));
  // Concurrentes: el orden final lo fija prioritize, no la llegada de los eventos.
  const collected = await Promise.all(
    active.map((s) => collect(s.scanner, s.category, ctx, salt, deps.hash)),
  );

  const categories = buildCategories(collected, opts.skipped);
  const statuses = mapCategories((c) => categories[c].status);

  let findings = prioritize(
    applyBaseline(
      [
        ...dedupeSecrets(collected.flatMap((c) => c.secrets)),
        ...collected.flatMap((c) => c.findings),
      ],
      load,
    ),
  );
  let code = exitCode(findings, opts.failOn, statuses);

  if (opts.updateBaseline) {
    const outcome = updateBaseline({ load, findings, statuses, history: opts.history, salt });
    if (outcome.kind === "refused") {
      warnings.push({ code: "BASELINE_UPDATE_REFUSED", reason: outcome.reason });
      code = 2;
    } else {
      try {
        await deps.baseline.save(outcome.baseline);
        findings = applyBaseline(findings, { kind: "valid", baseline: outcome.baseline });
        code = exitCode(findings, opts.failOn, statuses);
      } catch {
        // Sin el mensaje: puede incluir rutas o datos del adaptador. El informe no se pierde.
        warnings.push({ code: "BASELINE_SAVE_FAILED" });
        code = 2;
      }
    }
  }

  return {
    kind: "ok",
    exitCode: code,
    result: {
      schemaVersion: 1,
      tool: { name: "repoguard", version: opts.toolVersion, rulesetVersion: opts.rulesetVersion },
      // Campo a campo: lo que añada el adaptador de git no entra en el contrato JSON.
      target: {
        root: repo.info.root,
        ...(repo.info.headCommit !== undefined && { headCommit: repo.info.headCommit }),
        shallow: repo.info.shallow,
      },
      categories,
      warnings,
      findings,
      durationMs: deps.clock() - started,
    },
  };
}

async function describeRepo(repo: Pick<RepoReader, "describe">): Promise<RepoDescription> {
  try {
    return sanitizeRepoDescription(await repo.describe());
  } catch {
    return { kind: "fatal", code: "REPO_ERROR" };
  }
}

/** Lee la categoría de cada escáner una sola vez; null si alguna no es válida o lanza. */
function categorize(
  scanners: readonly Scanner[],
): { scanner: Scanner; category: Category }[] | null {
  try {
    const out = scanners.map((scanner) => ({ scanner, category: scanner.category as unknown }));
    return out.every((s) => isOneOf(CATEGORIES, s.category))
      ? (out as { scanner: Scanner; category: Category }[])
      : null;
  } catch {
    return null;
  }
}

/**
 * Un fallo al leer el baseline, o una forma inesperada, se trata como baseline inválido:
 * no suprime ni se sobrescribe. La sal y los fingerprints se normalizan (sanitize-adapter).
 */
async function loadBaseline(store: BaselineStore): Promise<BaselineLoad> {
  try {
    return sanitizeBaselineLoad(await store.load());
  } catch {
    return { kind: "invalid" };
  }
}

/** Ejecuta un escáner aislado: sus errores marcan su categoría, nunca abortan el scan (§2.2). */
async function collect(
  scanner: Scanner,
  category: Category,
  ctx: ScanContext,
  salt: string,
  hash: Hasher,
): Promise<Collected> {
  const out: Collected = {
    category,
    status: "complete",
    warnings: [],
    findings: [],
    secrets: [],
  };
  const fail = (code: WarningCode) => {
    out.status = "incomplete";
    out.warnings.push({ code });
  };

  try {
    for await (const event of scanner.scan(ctx)) {
      if (!accept(event, out, salt, hash)) {
        fail("SCANNER_CONTRACT_VIOLATION");
        break;
      }
    }
  } catch {
    // Sin el mensaje ni el stack: podrían contener la línea que se estaba analizando.
    fail("SCANNER_FAILED");
  }
  return out;
}

/**
 * Incorpora un evento; devuelve false si viola el contrato del puerto Scanner.
 * El evento se trata como `unknown`: se valida y reconstruye en runtime (policy/sanitize-event).
 */
function accept(event: unknown, out: Collected, salt: string, hash: Hasher): boolean {
  if (typeof event !== "object" || event === null) return false;
  // Cada campo se lee una sola vez (ver policy/sanitize-event).
  const {
    type,
    warning: rawWarning,
    status,
    match: rawMatch,
    finding,
    anchor,
  } = event as Record<string, unknown>;
  switch (type) {
    case "warning": {
      const warning = sanitizeWarning(rawWarning);
      if (!warning) return false;
      out.warnings.push(warning);
      return true;
    }
    case "status":
      if (status !== "incomplete") return false;
      out.status = "incomplete";
      return true;
    case "secret": {
      if (out.category !== "secret") return false;
      const match = sanitizeSecretMatch(rawMatch);
      if (!match) return false;
      // Aquí se descarta el SecretValue: SecretOccurrence solo lleva fingerprint y redacción.
      out.secrets.push(secretDraft(match, salt, hash));
      return true;
    }
    case "finding": {
      const draft = sanitizeFindingDraft(finding, out.category);
      if (!draft || typeof anchor !== "string") return false;
      const id = findingId(draft, anchor, hash);
      if (id === null) return false;
      out.findings.push({ ...draft, id, suppressed: false });
      return true;
    }
    default:
      return false;
  }
}

function buildCategories(
  collected: readonly Collected[],
  skipped: readonly Category[],
): Record<Category, CategoryReport> {
  return mapCategories((category) => {
    if (skipped.includes(category)) return { status: "skipped", warnings: [] };
    const mine = collected.filter((c) => c.category === category);
    return {
      status: mine.some((c) => c.status === "incomplete") ? "incomplete" : "complete",
      warnings: mine.flatMap((c) => c.warnings),
    };
  });
}

function mapCategories<T>(fn: (c: Category) => T): Record<Category, T> {
  return Object.fromEntries(CATEGORIES.map((c) => [c, fn(c)])) as Record<Category, T>;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
