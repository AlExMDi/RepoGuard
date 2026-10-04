import { describe, expect, it } from "vitest";
import type { Category } from "../domain/finding";
import type { CategoryStatus } from "../domain/scan-result";
import { exitCode } from "./exit-code";
import { f } from "./test-findings";

const statuses = (s: Partial<Record<Category, CategoryStatus>> = {}) => ({
  secret: "complete" as CategoryStatus,
  dependency: "complete" as CategoryStatus,
  misconfig: "complete" as CategoryStatus,
  ...s,
});

describe("exitCode (mvp §4.2)", () => {
  it.each([
    // [descripción, failOn, hallazgos, estados, esperado]
    ["sin hallazgos", "high", [], {}, 0],
    ["hallazgo bajo el umbral", "high", [f("1", "medium")], {}, 0],
    ["hallazgo en el umbral", "high", [f("1", "high")], {}, 1],
    ["hallazgo sobre el umbral", "high", [f("1", "critical")], {}, 1],
    ["suprimido no cuenta", "high", [f("1", "critical", "secret", { suppressed: true })], {}, 0],
    ["failOn low cuenta todo", "low", [f("1", "low")], {}, 1],
    ["failOn none nunca da 1", "none", [f("1", "critical")], {}, 0],
    ["incompleto sin hallazgos", "high", [], { dependency: "incomplete" }, 2],
    ["incompleto + bajo umbral", "high", [f("1", "low")], { dependency: "incomplete" }, 2],
    ["incompleto + ≥ umbral gana 1", "high", [f("1", "high")], { dependency: "incomplete" }, 1],
    ["incompleto + failOn none", "none", [f("1", "critical")], { secret: "incomplete" }, 2],
    ["skipped no es incompleto", "high", [], { dependency: "skipped" }, 0],
  ] as const)("%s", (_, failOn, findings, s, expected) => {
    expect(exitCode([...findings], failOn, statuses(s))).toBe(expected);
  });
});
