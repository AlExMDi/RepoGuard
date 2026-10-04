import type { Category, FailOn, Finding } from "../domain/finding";
import type { CategoryReport, CategoryStatus, ScanResult } from "../domain/scan-result";
import type { Warning, WarningCode } from "../domain/warning";
import type { BaselineLoad, BaselineStore } from "../ports/baseline-store";
import type { Clock } from "../ports/clock";
import type { Hasher, RandomBytes } from "../ports/crypto";
import type { RepoFatalCode, RepoReader } from "../ports/repo-reader";
import type { ScanContext, Scanner, ScannerEvent } from "../ports/scanner";
import { applyBaseline } from "../policy/apply-baseline";
import { dedupeSecrets } from "../policy/dedupe-secrets";
import { exitCode } from "../policy/exit-code";
import { findingId } from "../policy/finding-id";
import { prioritize } from "../policy/prioritize";
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

export type RunScanOutcome =
  | { kind: "ok"; result: ScanResult; exitCode: 0 | 1 | 2 }
  | { kind: "fatal"; code: RepoFatalCode; exitCode: 2 };

const CATEGORIES: readonly Category[] = ["secret", "dependency", "misconfig"];

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
 * puertos. Los errores de repo se devuelven como `fatal`, nunca como excepción.
 */
export async function runScan(deps: RunScanDeps, opts: RunScanOptions): Promise<RunScanOutcome> {
  const started = deps.clock();

  const repo = await deps.repo.describe();
  if (repo.kind === "fatal") return { kind: "fatal", code: repo.code, exitCode: 2 };

  const warnings: Warning[] = [];
  if (repo.info.shallow) warnings.push({ code: "SHALLOW_CLONE" });

  const load = await loadBaseline(deps.baseline);
  if (load.kind === "invalid") warnings.push({ code: "BASELINE_INVALID" });
  const salt = load.kind === "valid" ? load.baseline.salt : toHex(deps.random(32));

  const ctx: ScanContext = { repo: repo.info, history: opts.history };
  const active = deps.scanners.filter((s) => !opts.skipped.includes(s.category));
  // Concurrentes: el orden final lo fija prioritize, no la llegada de los eventos.
  const collected = await Promise.all(active.map((s) => collect(s, ctx, salt, deps.hash)));

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
      await deps.baseline.save(outcome.baseline);
      findings = applyBaseline(findings, { kind: "valid", baseline: outcome.baseline });
      code = exitCode(findings, opts.failOn, statuses);
    }
  }

  return {
    kind: "ok",
    exitCode: code,
    result: {
      schemaVersion: 1,
      tool: { name: "repoguard", version: opts.toolVersion, rulesetVersion: opts.rulesetVersion },
      target: repo.info,
      categories,
      warnings,
      findings,
      durationMs: deps.clock() - started,
    },
  };
}

/** Un fallo al leer el baseline se trata como baseline inválido: no suprime ni se sobrescribe. */
async function loadBaseline(store: BaselineStore): Promise<BaselineLoad> {
  try {
    return await store.load();
  } catch {
    return { kind: "invalid" };
  }
}

/** Ejecuta un escáner aislado: sus errores marcan su categoría, nunca abortan el scan (§2.2). */
async function collect(
  scanner: Scanner,
  ctx: ScanContext,
  salt: string,
  hash: Hasher,
): Promise<Collected> {
  const out: Collected = {
    category: scanner.category,
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

/** Incorpora un evento; devuelve false si viola el contrato del puerto Scanner. */
function accept(event: ScannerEvent, out: Collected, salt: string, hash: Hasher): boolean {
  switch (event.type) {
    case "warning":
      out.warnings.push(pickWarning(event.warning));
      return true;
    case "status":
      out.status = "incomplete";
      return true;
    case "secret":
      if (out.category !== "secret") return false;
      // Aquí se descarta el SecretValue: SecretOccurrence solo lleva fingerprint y redacción.
      out.secrets.push(secretDraft(event.match, salt, hash));
      return true;
    case "finding": {
      if (event.finding.category !== out.category) return false;
      const id = findingId(event.finding, event.anchor, hash);
      if (id === null) return false;
      out.findings.push({ ...event.finding, id, suppressed: false });
      return true;
    }
  }
}

/** Copia solo los campos conocidos: un escáner con un bug no puede colar texto libre. */
function pickWarning(w: Warning): Warning {
  return {
    code: w.code,
    ...(w.path !== undefined && { path: w.path }),
    ...(w.count !== undefined && { count: w.count }),
    ...(w.reason !== undefined && { reason: w.reason }),
  };
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
