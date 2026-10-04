import type { Finding } from "../domain/finding";
import { CATEGORY_RANK, SEVERITY_RANK } from "./severity";

/** Ruta y línea comparables para cualquier ubicación: los paquetes usan el lockfile y no tienen línea. */
function where(x: Finding): { path: string; line: number } {
  return x.location.kind === "file"
    ? { path: x.location.path, line: x.location.line ?? 0 }
    : { path: x.location.lockfile, line: 0 };
}

const inTree = (x: Finding): boolean => x.secret?.inWorkingTree ?? false;

/**
 * Orden de mvp §2.6: severidad desc → categoría (secret > dependency > misconfig) →
 * inWorkingTree primero → ruta → línea. Negativo si `a` va antes que `b`.
 */
export function compareFindings(a: Finding, b: Finding): number {
  if (SEVERITY_RANK[a.severity] !== SEVERITY_RANK[b.severity]) {
    return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  }

  if (CATEGORY_RANK[a.category] !== CATEGORY_RANK[b.category]) {
    return CATEGORY_RANK[b.category] - CATEGORY_RANK[a.category];
  }

  if (inTree(a) !== inTree(b)) {
    return inTree(b) ? 1 : -1;
  }

  const aWhere = where(a);
  const bWhere = where(b);

  if (aWhere.path !== bWhere.path) {
    return aWhere.path < bWhere.path ? -1 : 1;
  }

  return aWhere.line - bWhere.line;
}

/** Devuelve una copia ordenada; no muta la entrada. */
export function prioritize(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(compareFindings);
}
