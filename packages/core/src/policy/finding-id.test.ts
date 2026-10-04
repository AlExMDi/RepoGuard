import { describe, expect, it } from "vitest";
import type { Hasher } from "../ports/crypto";
import type { FindingDraft } from "../ports/scanner";
import { findingId } from "./finding-id";

const identityHex: Hasher = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const misconfig = (path: string, line: number, ruleId = "gha-write-all"): FindingDraft => ({
  category: "misconfig",
  ruleId,
  severity: "medium",
  title: "t",
  location: { kind: "file", path, line },
});

const dep = (version: string, osvId = "GHSA-xxxx"): FindingDraft => ({
  category: "dependency",
  ruleId: osvId,
  severity: "high",
  title: "t",
  location: { kind: "package", lockfile: "pnpm-lock.yaml", ecosystem: "npm", name: "lodash", version },
  vuln: { osvId, aliases: [], url: "https://osv.dev/x" },
});

describe("findingId", () => {
  it("misconfig: estable aunque cambie la línea", () => {
    expect(findingId(misconfig("a.yml", 3), "job:build", identityHex)).toBe(
      findingId(misconfig("a.yml", 40), "job:build", identityHex),
    );
  });

  it("misconfig: cambia con anchor, ruta o regla", () => {
    const base = findingId(misconfig("a.yml", 3), "job:build", identityHex);
    expect(findingId(misconfig("a.yml", 3), "job:test", identityHex)).not.toBe(base);
    expect(findingId(misconfig("b.yml", 3), "job:build", identityHex)).not.toBe(base);
    expect(findingId(misconfig("a.yml", 3, "docker-root-user"), "job:build", identityHex)).not.toBe(base);
  });

  it("dependency: cambia con versión u osvId y no depende del anchor", () => {
    const base = findingId(dep("4.17.20"), "", identityHex);
    expect(findingId(dep("4.17.20"), "otro", identityHex)).toBe(base);
    expect(findingId(dep("4.17.21"), "", identityHex)).not.toBe(base);
    expect(findingId(dep("4.17.20", "GHSA-yyyy"), "", identityHex)).not.toBe(base);
  });

  it("la codificación no es ambigua: [a, bc] ≠ [ab, c]", () => {
    expect(findingId(misconfig("a", 1, "x"), "bc", identityHex)).not.toBe(
      findingId(misconfig("ab", 1, "x"), "c", identityHex),
    );
  });

  it("devuelve null si la forma no encaja con la categoría", () => {
    const noVuln: FindingDraft = { ...dep("1.0.0") };
    delete noVuln.vuln;
    expect(findingId(noVuln, "", identityHex)).toBeNull();
    expect(findingId({ ...misconfig("a", 1), location: dep("1").location }, "", identityHex)).toBeNull();
    expect(findingId({ ...misconfig("a", 1), category: "secret" }, "", identityHex)).toBeNull();
  });
});
