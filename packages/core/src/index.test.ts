import { describe, expect, it } from "vitest";
import * as core from "./index";

describe("API pública de @repoguard/core", () => {
  it("exporta en runtime solo SecretValue y runScan", () => {
    // Los tipos no existen en runtime; esto fija los valores exportados. Las políticas y
    // los dobles de testing/ son internos: exportarlos sería un contrato difícil de retirar.
    expect(Object.keys(core).sort()).toEqual(["SecretValue", "runScan"]);
  });
});
