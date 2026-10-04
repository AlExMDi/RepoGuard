import type { Finding } from "../domain/finding";
import type { SecretOccurrence } from "./secret-draft";

// Primera aparición: menor ordinal; desempate por ruta, línea y columna (determinista).
function earlier(a: SecretOccurrence, b: SecretOccurrence): boolean {
  if (a.ordinal !== b.ordinal) return a.ordinal < b.ordinal;
  if (a.location.path !== b.location.path) return a.location.path < b.location.path;
  if (a.location.line !== b.location.line) return a.location.line < b.location.line;
  return a.location.column < b.location.column;
}

/** Un hallazgo por fingerprint, con la primera aparición como ubicación (spec §2.4). */
export function dedupeSecrets(occurrences: readonly SecretOccurrence[]): Finding[] {
  const groups = new Map<string, { first: SecretOccurrence; count: number; inTree: boolean }>();
  for (const o of occurrences) {
    const g = groups.get(o.fingerprint);
    if (!g) {
      groups.set(o.fingerprint, { first: o, count: 1, inTree: o.inWorkingTree });
      continue;
    }
    g.count++;
    g.inTree ||= o.inWorkingTree;
    if (earlier(o, g.first)) g.first = o;
  }

  return [...groups.values()]
    .sort((a, b) => (earlier(a.first, b.first) ? -1 : 1))
    .map(({ first, count, inTree }) => ({
      id: first.fingerprint,
      category: "secret",
      ruleId: first.ruleId,
      severity: first.severity,
      title: first.title,
      location: { kind: "file", ...first.location },
      secret: { redacted: first.redacted, length: first.length, inWorkingTree: inTree, occurrences: count },
      suppressed: false,
    }));
}
