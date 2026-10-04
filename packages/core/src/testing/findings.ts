import type { Category, Finding, Severity } from "../domain/finding";

/** Constructor compacto de hallazgos para tests de políticas. */
export function f(
  id: string,
  severity: Severity,
  category: Category = "secret",
  extra: { path?: string; line?: number; inWorkingTree?: boolean; suppressed?: boolean } = {},
): Finding {
  const { path = "a", line = 1, inWorkingTree = false, suppressed = false } = extra;
  return {
    id,
    category,
    ruleId: "r",
    severity,
    title: "t",
    location:
      category === "dependency"
        ? { kind: "package", lockfile: path, ecosystem: "npm", name: "p", version: "1" }
        : { kind: "file", path, line },
    ...(category === "secret"
      ? { secret: { redacted: "x****", length: 20, inWorkingTree, occurrences: 1 } }
      : {}),
    suppressed,
  };
}
