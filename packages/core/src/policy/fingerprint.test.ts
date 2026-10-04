import { describe, expect, it } from "vitest";
import { SecretValue } from "../domain/secret-value";
import type { Hasher } from "../ports/crypto";
import { fingerprint } from "./fingerprint";

// Devuelve los bytes recibidos en hex: permite comprobar la disposición exacta.
const identityHex: Hasher = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const SALT = "ab".repeat(32);

describe("fingerprint", () => {
  it("hashea salt ‖ 0x00 ‖ ruleId ‖ 0x00 ‖ secreto (UTF-8)", () => {
    const out = fingerprint({ salt: SALT, ruleId: "r", value: new SecretValue("sé") }, identityHex);
    // "r" = 72, "sé" = 73 c3 a9
    expect(out).toBe(`${SALT}00` + "72" + "00" + "73c3a9");
  });

  it("es determinista y depende de sal, regla y secreto", () => {
    const base = { salt: SALT, ruleId: "aws-access-key", value: new SecretValue("v1") };
    const fp = (o: Partial<typeof base>) => fingerprint({ ...base, ...o }, identityHex);
    expect(fp({})).toBe(fp({}));
    expect(fp({ salt: "cd".repeat(32) })).not.toBe(fp({}));
    expect(fp({ ruleId: "github-pat" })).not.toBe(fp({}));
    expect(fp({ value: new SecretValue("v2") })).not.toBe(fp({}));
  });

  it("rechaza sales que no son 32 bytes en hex", () => {
    for (const salt of ["", "ab", "zz".repeat(32), "ab".repeat(33)]) {
      expect(() =>
        fingerprint({ salt, ruleId: "r", value: new SecretValue("v") }, identityHex),
      ).toThrow(/salt/);
    }
  });
});
