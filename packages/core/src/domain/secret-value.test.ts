import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { Finding } from "./finding";
import { SecretValue } from "./secret-value";
import type { Warning } from "./warning";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

// Todas las vías por las que un valor acaba convertido en texto sin querer.
function serializations(v: SecretValue): string[] {
  const inspect = (v as unknown as Record<symbol, () => unknown>)[INSPECT];
  return [
    String(v),
    `${v}`,
    "" + v,
    JSON.stringify(v),
    JSON.stringify({ v }),
    JSON.stringify([v]),
    String(v.valueOf()),
    String(inspect?.call(v)),
    Object.keys(v).join(","),
    JSON.stringify(Object.entries(v)),
  ];
}

describe("SecretValue", () => {
  it("se serializa siempre como [REDACTED]", () => {
    const v = new SecretValue("not-a-real-token-1234567890");
    expect(String(v)).toBe("[REDACTED]");
    expect(JSON.stringify({ v })).toBe('{"v":"[REDACTED]"}');
    expect(v.valueOf()).toBe("[REDACTED]");
  });

  it("no expone el valor por ninguna serialización (property)", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 12 }), (raw) => {
        fc.pre(!"[REDACTED]".includes(raw));
        const v = new SecretValue(raw);
        for (const out of serializations(v)) expect(out).not.toContain(raw);
      }),
    );
  });

  it("conserva longitud y valor original", () => {
    fc.assert(
      fc.property(fc.string(), (raw) => {
        const v = new SecretValue(raw);
        expect(v.length).toBe(raw.length);
        expect(v.unsafeReveal()).toBe(raw);
      }),
    );
  });

  describe("a prueba de imitaciones (revisión de seguridad M-2)", () => {
    const real = new SecretValue("not-a-real-token-1234567890");

    it("isGenuine solo acepta instancias reales, no Proxies ni objetos imitados", () => {
      expect(SecretValue.isGenuine(real)).toBe(true);
      expect(SecretValue.isGenuine(new Proxy(real, {}))).toBe(false);
      expect(SecretValue.isGenuine(Object.create(SecretValue.prototype))).toBe(false);
      expect(SecretValue.isGenuine({ length: 3 })).toBe(false);
      expect(SecretValue.isGenuine(null)).toBe(false);
      expect(SecretValue.isGenuine("texto")).toBe(false);
    });

    it("lengthOf lee el campo privado: una subclase no puede falsear la longitud", () => {
      class Evil extends SecretValue {
        override get length(): number {
          return 999;
        }
      }
      const evil = new Evil("abc");
      expect(evil.length).toBe(999);
      expect(SecretValue.lengthOf(evil)).toBe(3);
    });
  });

  describe("oráculos acotados (revisión de seguridad B-1, M-3)", () => {
    const v = new SecretValue("not-a-real-token-1234567890");

    it("hasPrefix solo responde para prefijos de hasta 12 caracteres", () => {
      expect(SecretValue.hasPrefix(v, "not-")).toBe(true);
      expect(SecretValue.hasPrefix(v, "ghp_")).toBe(false);
      // 13 caracteres correctos: false, para que no sirva para adivinar el secreto entero.
      expect(SecretValue.hasPrefix(v, "not-a-real-to")).toBe(false);
    });

    it("occursIn detecta el valor completo dentro de un texto", () => {
      expect(SecretValue.occursIn(v, "line: TOKEN=not-a-real-token-1234567890")).toBe(true);
      expect(SecretValue.occursIn(v, "Fake token")).toBe(false);
      expect(SecretValue.occursIn(new SecretValue(""), "cualquier cosa")).toBe(false);
    });
  });

  it("los tipos públicos no admiten material secreto ni texto libre", () => {
    const v = new SecretValue("x");
    const secret: NonNullable<Finding["secret"]> = {
      // @ts-expect-error redacted es string, no SecretValue
      redacted: v,
      length: 1,
      inWorkingTree: true,
      occurrences: 1,
    };
    // @ts-expect-error Warning no tiene campo de texto libre
    const w: Warning = { code: "SCANNER_FAILED", message: "boom" };
    expect([secret, w]).toHaveLength(2);
  });
});
