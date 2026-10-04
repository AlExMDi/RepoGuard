import type { Baseline } from "../domain/baseline";
import type { Category, Finding } from "../domain/finding";
import type { CategoryStatus } from "../domain/scan-result";
import type { WarningReason } from "../domain/warning";
import type { BaselineLoad } from "../ports/baseline-store";

export interface UpdateBaselineInput {
  load: BaselineLoad;
  findings: readonly Finding[];
  statuses: Record<Category, CategoryStatus>;
  /** false con --no-history. */
  history: boolean;
  /** La sal con la que se calcularon los fingerprints de este scan. */
  salt: string;
}

export type UpdateBaselineOutcome =
  { kind: "updated"; baseline: Baseline } | { kind: "refused"; reason: WarningReason };

/**
 * Reescribe el baseline con los hallazgos actuales (spec finding-runscan §2.5).
 * Se niega si el baseline existente es inválido (se perderían sal y notas) o si el scan
 * fue parcial (se borrarían entradas que el scan no pudo ver).
 */
export function updateBaseline(input: UpdateBaselineInput): UpdateBaselineOutcome {
  const { load, findings, statuses, history, salt } = input;

  // Primero el baseline inválido: es un problema del fichero, que el usuario debe arreglar
  // aunque repita el scan completo.
  if (load.kind === "invalid") return { kind: "refused", reason: "invalid-baseline" };
  if (!history || Object.values(statuses).some((s) => s !== "complete")) {
    return { kind: "refused", reason: "partial-scan" };
  }

  const notes = new Map(
    load.kind === "valid" ? load.baseline.entries.map((e) => [e.fingerprint, e.note]) : [],
  );
  const entries = findings
    .map((x) => ({ fingerprint: x.id, ruleId: x.ruleId, note: notes.get(x.id) ?? "" }))
    // Por código, como prioritize: el diff del baseline no depende del idioma del sistema.
    .sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0));

  return { kind: "updated", baseline: { version: 1, salt, entries } };
}
