import type { Category, FailOn, Finding } from "../domain/finding";
import type { CategoryStatus } from "../domain/scan-result";
import { SEVERITY_RANK } from "./severity";

/**
 * 0 limpio · 1 hallazgos no suprimidos ≥ failOn · 2 scan incompleto (mvp §4.2).
 * Si hay hallazgos ≥ umbral y además el scan está incompleto, gana 1.
 */
export function exitCode(
  findings: readonly Finding[],
  failOn: FailOn,
  statuses: Record<Category, CategoryStatus>,
): 0 | 1 | 2 {
  if (failOn !== "none") {
    const threshold = SEVERITY_RANK[failOn];
    if (findings.some((x) => !x.suppressed && SEVERITY_RANK[x.severity] >= threshold)) return 1;
  }
  return Object.values(statuses).includes("incomplete") ? 2 : 0;
}
