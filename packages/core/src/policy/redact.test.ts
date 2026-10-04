import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { SecretValue } from "../domain/secret-value";
import { redact } from "./redact";

describe("redact", () => {
  it("muestra solo el prefijo público y la longitud", () => {
    const value = new SecretValue("ghp_" + "a1".repeat(18));
    expect(redact({ publicPrefix: "ghp_", kindLabel: "GitHub PAT", value })).toEqual({
      redacted: "ghp_****",
      length: 40,
    });
  });

  it("reglas sin prefijo muestran solo el tipo", () => {
    const value = new SecretValue("-----material de clave-----");
    expect(redact({ publicPrefix: null, kindLabel: "private key, RSA", value })).toEqual({
      redacted: "[private key, RSA]",
      length: 27,
    });
  });

  it("la longitud no se puede falsear con una subclase", () => {
    class Evil extends SecretValue {
      override get length(): number {
        return 999;
      }
    }
    const value = new Evil("not-abc");
    expect(redact({ publicPrefix: "not-", kindLabel: "k", value }).length).toBe(7);
  });

  it("nunca contiene caracteres posteriores al prefijo (property)", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 12 }),
        fc.string({ minLength: 4 }),
        (prefix, rest) => {
          const { redacted } = redact({
            publicPrefix: prefix,
            kindLabel: "k",
            value: new SecretValue(prefix + rest),
          });
          expect(redacted.startsWith(prefix)).toBe(true);
          expect(redacted.slice(prefix.length)).toMatch(/^\*+$/);
        },
      ),
    );
  });
});
