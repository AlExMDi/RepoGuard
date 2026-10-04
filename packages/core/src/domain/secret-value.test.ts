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
