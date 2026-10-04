import type { Category, Finding } from "./finding";
import type { Warning } from "./warning";

export type CategoryStatus = "complete" | "incomplete" | "skipped";

export interface CategoryReport {
  status: CategoryStatus;
  warnings: Warning[];
}

/** Contrato JSON estable (mvp §4.3). */
export interface ScanResult {
  schemaVersion: 1;
  tool: { name: "repoguard"; version: string; rulesetVersion: string };
  target: { root: string; headCommit?: string; shallow: boolean };
  categories: Record<Category, CategoryReport>;
  /** Avisos que no pertenecen a una categoría: caché, baseline, clon superficial. */
  warnings: Warning[];
  /** Ya ordenados (mvp §2.6). */
  findings: Finding[];
  durationMs: number;
}
