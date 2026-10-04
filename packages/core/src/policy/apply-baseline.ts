import type { Finding } from "../domain/finding";
import type { BaselineLoad } from "../ports/baseline-store";

/** Marca como suprimidos los hallazgos cuyo id está en un baseline válido (mvp §2.5). */
export function applyBaseline(findings: readonly Finding[], load: BaselineLoad): Finding[] {
  if (load.kind !== "valid") return findings.map((x) => ({ ...x, suppressed: false }));
  const known = new Set(load.baseline.entries.map((e) => e.fingerprint));
  return findings.map((x) => ({ ...x, suppressed: known.has(x.id) }));
}
