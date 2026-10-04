import type { Category, Finding } from "../domain/finding";
import type { RawSecretMatch } from "../domain/raw-secret-match";
import type { Warning } from "../domain/warning";
import type { RepoInfo } from "./repo-reader";

/** Hallazgo de deps o misconfig antes de que runScan le asigne id y supresión. Sin `secret`: los secretos llegan solo como RawSecretMatch. */
export type FindingDraft = Omit<Finding, "id" | "suppressed" | "secret">;

export type ScannerEvent =
  /** `anchor`: clave semántica estable sin número de línea (spec finding-runscan §2.3). */
  | { type: "finding"; finding: FindingDraft; anchor: string }
  | { type: "secret"; match: RawSecretMatch }
  | { type: "warning"; warning: Warning }
  /** El escáner no pudo completar su trabajo (p. ej. OSV caído). */
  | { type: "status"; status: "incomplete" };

export interface ScanContext {
  repo: RepoInfo;
  /** false con --no-history: solo árbol de trabajo. */
  history: boolean;
}

export interface Scanner {
  readonly category: Category;
  scan(ctx: ScanContext): AsyncIterable<ScannerEvent>;
}
