import { describe, expect, it } from "vitest";
import type { RawSecretMatch } from "../domain/raw-secret-match";
import { SecretValue } from "../domain/secret-value";
import type { Hasher } from "../ports/crypto";
import { dedupeSecrets } from "./dedupe-secrets";
import { secretDraft } from "./secret-draft";

const hash: Hasher = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const SALT = "00".repeat(32);
const RAW = "not-a-real-token-abcdefghijklmnop";

function match(over: Partial<RawSecretMatch> & Pick<RawSecretMatch, "ordinal">): RawSecretMatch {
  return {
    ruleId: "fake-rule",
    severity: "high",
    title: "Fake token",
    publicPrefix: "not-",
    kindLabel: "fake",
    value: new SecretValue(RAW),
    location: { path: "a.txt", line: 1, column: 1 },
    inWorkingTree: false,
    ...over,
  };
}

const drafts = (ms: RawSecretMatch[]) => ms.map((m) => secretDraft(m, SALT, hash));

describe("secretDraft", () => {
  it("no conserva el valor en claro", () => {
    const d = secretDraft(match({ ordinal: 0 }), SALT, hash);
    expect(JSON.stringify(d)).not.toContain(RAW);
    expect(Object.values(d).some((v) => v instanceof SecretValue)).toBe(false);
    expect(d.redacted).toBe("not-****");
  });
});

describe("dedupeSecrets", () => {
  const leak = [
    match({ ordinal: 2, location: { path: "b.txt", line: 5, column: 3, commit: "c2" } }),
    match({ ordinal: 9, location: { path: "a.txt", line: 1, column: 1 }, inWorkingTree: true }),
    match({ ordinal: 0, location: { path: "c.txt", line: 7, column: 2, commit: "c0" } }),
    match({ ordinal: 1, location: { path: "c.txt", line: 7, column: 2, commit: "c1" } }),
  ];

  it("3 commits + árbol → 1 hallazgo con la primera aparición", () => {
    const [f, ...rest] = dedupeSecrets(drafts(leak));
    expect(rest).toEqual([]);
    expect(f).toMatchObject({
      category: "secret",
      ruleId: "fake-rule",
      location: { kind: "file", path: "c.txt", line: 7, column: 2, commit: "c0" },
      secret: { redacted: "not-****", length: RAW.length, inWorkingTree: true, occurrences: 4 },
      suppressed: false,
    });
  });

  it("el orden de entrada no cambia la salida", () => {
    const a = dedupeSecrets(drafts(leak));
    const b = dedupeSecrets(drafts([...leak].reverse()));
    expect(b).toEqual(a);
  });

  it("a igual ordinal desempata por ruta, línea y columna", () => {
    const tie = [
      match({ ordinal: 0, location: { path: "b", line: 1, column: 1 } }),
      match({ ordinal: 0, location: { path: "a", line: 2, column: 1 } }),
      match({ ordinal: 0, location: { path: "a", line: 1, column: 9 } }),
      match({ ordinal: 0, location: { path: "a", line: 1, column: 4 } }),
    ];
    const [f] = dedupeSecrets(drafts(tie));
    expect(f?.location).toEqual({ kind: "file", path: "a", line: 1, column: 4 });
  });

  it("secretos distintos o reglas distintas no se fusionan", () => {
    const other = match({ ordinal: 3, value: new SecretValue(RAW + "x") });
    const otherRule = match({ ordinal: 4, ruleId: "fake-rule-2" });
    expect(dedupeSecrets(drafts([...leak, other, otherRule]))).toHaveLength(3);
  });
});
