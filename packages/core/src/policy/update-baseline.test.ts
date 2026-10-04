import { describe, expect, it } from "vitest";
import type { Baseline } from "../domain/baseline";
import type { Category } from "../domain/finding";
import type { CategoryStatus } from "../domain/scan-result";
import { f } from "../testing/findings";
import { updateBaseline, type UpdateBaselineInput } from "./update-baseline";

const SALT = "ab".repeat(32);
const complete: Record<Category, CategoryStatus> = {
  secret: "complete",
  dependency: "complete",
  misconfig: "complete",
};

const existing: Baseline = {
  version: 1,
  salt: SALT,
  entries: [
    { fingerprint: "fp-b", ruleId: "r", note: "rotado el 2026-09-01" },
    { fingerprint: "fp-old", ruleId: "r", note: "ya no existe" },
  ],
};

function input(over: Partial<UpdateBaselineInput> = {}): UpdateBaselineInput {
  return {
    load: { kind: "valid", baseline: existing },
    findings: [
      f("fp-c", "high"),
      f("fp-b", "low", "misconfig", { suppressed: true }),
      f("fp-a", "medium"),
    ],
    statuses: complete,
    history: true,
    salt: SALT,
    ...over,
  };
}

describe("updateBaseline (spec finding-runscan §2.5)", () => {
  it("las entradas son exactamente los hallazgos actuales, ordenadas por fingerprint", () => {
    const out = updateBaseline(input());
    expect(out.kind).toBe("updated");
    if (out.kind !== "updated") return;
    expect(out.baseline.entries.map((e) => e.fingerprint)).toEqual(["fp-a", "fp-b", "fp-c"]);
  });

  it("conserva sal y notas de las entradas vigentes y elimina las obsoletas", () => {
    const out = updateBaseline(input());
    if (out.kind !== "updated") throw new Error("esperaba updated");
    expect(out.baseline).toEqual({
      version: 1,
      salt: SALT,
      entries: [
        { fingerprint: "fp-a", ruleId: "r", note: "" },
        { fingerprint: "fp-b", ruleId: "r", note: "rotado el 2026-09-01" },
        { fingerprint: "fp-c", ruleId: "r", note: "" },
      ],
    });
  });

  it("sin baseline previo usa la sal del scan y notas vacías", () => {
    const salt = "cd".repeat(32);
    const out = updateBaseline(input({ load: { kind: "missing" }, salt }));
    if (out.kind !== "updated") throw new Error("esperaba updated");
    expect(out.baseline.salt).toBe(salt);
    expect(out.baseline.entries.every((e) => e.note === "")).toBe(true);
  });

  it("sin hallazgos produce un baseline vacío (no se niega)", () => {
    const out = updateBaseline(input({ findings: [] }));
    expect(out).toEqual({ kind: "updated", baseline: { version: 1, salt: SALT, entries: [] } });
  });

  it.each(["incomplete", "skipped"] as const)("se niega si una categoría está %s", (status) => {
    const out = updateBaseline(input({ statuses: { ...complete, dependency: status } }));
    expect(out).toEqual({ kind: "refused", reason: "partial-scan" });
  });

  it("se niega con --no-history", () => {
    expect(updateBaseline(input({ history: false }))).toEqual({
      kind: "refused",
      reason: "partial-scan",
    });
  });

  it("se niega si el baseline existente es inválido, aunque el scan sea parcial", () => {
    const out = updateBaseline(input({ load: { kind: "invalid" }, history: false }));
    expect(out).toEqual({ kind: "refused", reason: "invalid-baseline" });
  });
});
