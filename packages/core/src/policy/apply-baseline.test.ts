import { describe, expect, it } from "vitest";
import { applyBaseline } from "./apply-baseline";
import { f } from "./test-findings";

const findings = [f("fp1", "high"), f("fp2", "critical", "misconfig")];
const baseline = {
  version: 1 as const,
  salt: "00".repeat(32),
  entries: [{ fingerprint: "fp1", ruleId: "r", note: "" }],
};

describe("applyBaseline", () => {
  it("suprime por id, para cualquier categoría", () => {
    const out = applyBaseline(findings, {
      kind: "valid",
      baseline: {
        ...baseline,
        entries: [...baseline.entries, { fingerprint: "fp2", ruleId: "r", note: "" }],
      },
    });
    expect(out.map((x) => x.suppressed)).toEqual([true, true]);
  });

  it("solo suprime lo que está en el baseline", () => {
    expect(applyBaseline(findings, { kind: "valid", baseline }).map((x) => x.suppressed)).toEqual([
      true,
      false,
    ]);
  });

  it.each(["missing", "invalid"] as const)("baseline %s no suprime nada", (kind) => {
    expect(applyBaseline(findings, { kind }).map((x) => x.suppressed)).toEqual([false, false]);
  });

  it("no muta la entrada", () => {
    applyBaseline(findings, { kind: "valid", baseline });
    expect(findings[0]?.suppressed).toBe(false);
  });
});
