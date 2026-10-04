import { describe, expect, it } from "vitest";
import { sanitizeBaselineLoad, sanitizeRepoDescription } from "./sanitize-adapter";

const FP = "ab".repeat(32);
const SALT = "cd".repeat(32);
const valid = (baseline: unknown) => ({ kind: "valid", baseline });
const good = { version: 1, salt: SALT, entries: [{ fingerprint: FP, ruleId: "r", note: "n" }] };

describe("sanitizeBaselineLoad", () => {
  it("acepta un baseline válido y copia solo los campos conocidos", () => {
    const input = valid({ ...good, extra: 1, entries: [{ ...good.entries[0], x: 2 }] });
    expect(sanitizeBaselineLoad(input)).toEqual({ kind: "valid", baseline: good });
  });

  it("normaliza a minúsculas la sal y los fingerprints, conservando las notas (B-6)", () => {
    const upper = {
      ...good,
      salt: SALT.toUpperCase(),
      entries: [{ fingerprint: FP.toUpperCase(), ruleId: "r", note: "n" }],
    };
    expect(sanitizeBaselineLoad(valid(upper))).toEqual({ kind: "valid", baseline: good });
  });

  it.each([{ kind: "missing" }, { kind: "invalid" }])("respeta %o", (load) => {
    expect(sanitizeBaselineLoad(load)).toEqual(load);
  });

  it.each([
    ["no es objeto", null],
    ["kind desconocido", { kind: "ok" }],
    ["valid sin baseline", { kind: "valid" }],
    ["versión desconocida", valid({ ...good, version: 2 })],
    ["sal que no es hex", valid({ ...good, salt: "zz".repeat(32) })],
    ["sal que no es string", valid({ ...good, salt: 42 })],
    ["entries null", valid({ ...good, entries: null })],
    [
      "fingerprint corto",
      valid({ ...good, entries: [{ fingerprint: "ab", ruleId: "r", note: "" }] }),
    ],
    ["ruleId no string", valid({ ...good, entries: [{ fingerprint: FP, ruleId: 1, note: "" }] })],
    ["note no string", valid({ ...good, entries: [{ fingerprint: FP, ruleId: "r" }] })],
  ])("%s → invalid (nunca se ignora a medias)", (_, input) => {
    expect(sanitizeBaselineLoad(input)).toEqual({ kind: "invalid" });
  });
});

describe("sanitizeRepoDescription", () => {
  it("copia solo root, headCommit y shallow", () => {
    const input = { kind: "ok", info: { root: "/r", headCommit: "c", shallow: true, gitDir: "x" } };
    expect(sanitizeRepoDescription(input)).toEqual({
      kind: "ok",
      info: { root: "/r", headCommit: "c", shallow: true },
    });
  });

  it.each(["NOT_A_GIT_REPO", "GIT_MISSING", "REPO_ERROR"])("respeta el fatal %s", (code) => {
    expect(sanitizeRepoDescription({ kind: "fatal", code })).toEqual({ kind: "fatal", code });
  });

  it.each([
    ["no es objeto", undefined],
    ["ok sin info", { kind: "ok" }],
    ["root no string", { kind: "ok", info: { root: { x: 1 }, shallow: false } }],
    ["root vacío", { kind: "ok", info: { root: "", shallow: false } }],
    ["shallow no booleano", { kind: "ok", info: { root: "/r", shallow: "no" } }],
    ["código fatal desconocido", { kind: "fatal", code: "BOOM" }],
  ])("%s → fatal REPO_ERROR", (_, input) => {
    expect(sanitizeRepoDescription(input)).toEqual({ kind: "fatal", code: "REPO_ERROR" });
  });
});
