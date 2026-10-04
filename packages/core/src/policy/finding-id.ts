import type { Hasher } from "../ports/crypto";
import type { FindingDraft } from "../ports/scanner";

const utf8 = new TextEncoder();

/**
 * Id estable de deps y misconfig, sin número de línea (spec finding-runscan §2.3).
 * Codifica las partes como array JSON: sin ambigüedad aunque un campo contenga un separador.
 * Devuelve null si la forma del borrador no encaja con su categoría (violación de contrato).
 */
export function findingId(draft: FindingDraft, anchor: string, hash: Hasher): string | null {
  const { category, location } = draft;
  let parts: string[];

  if (category === "dependency" && location.kind === "package" && draft.vuln) {
    const { lockfile, ecosystem, name, version } = location;
    parts = ["dependency", draft.vuln.osvId, lockfile, ecosystem, name, version];
  } else if (category === "misconfig" && location.kind === "file") {
    parts = ["misconfig", draft.ruleId, location.path, anchor];
  } else {
    return null;
  }
  return hash(utf8.encode(JSON.stringify(parts)));
}
