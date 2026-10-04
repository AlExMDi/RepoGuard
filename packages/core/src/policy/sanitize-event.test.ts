import { describe, expect, it } from "vitest";
import { SecretValue } from "../domain/secret-value";
import { depEvent, misconfigEvent, RAW_SECRET, secretEvent } from "../testing/fakes";
import { sanitizeFindingDraft, sanitizeSecretMatch, sanitizeWarning } from "./sanitize-event";

// Lo que envía un escáner se trata como `unknown`: los tipos solo existen al compilar.
const CANARY = `TOKEN=${RAW_SECRET}`;

function draftOf(event: ReturnType<typeof depEvent>) {
  if (event.type !== "finding") throw new Error("esperaba finding");
  return event.finding;
}
function matchOf(event: ReturnType<typeof secretEvent>) {
  if (event.type !== "secret") throw new Error("esperaba secret");
  return event.match;
}

describe("sanitizeWarning", () => {
  it("copia solo los campos conocidos", () => {
    expect(
      sanitizeWarning({ code: "FILE_TOO_LARGE", path: "a.bin", count: 2, message: CANARY }),
    ).toEqual({
      code: "FILE_TOO_LARGE",
      path: "a.bin",
      count: 2,
    });
  });

  it.each([
    ["código desconocido", { code: CANARY }],
    ["reason desconocido", { code: "BASELINE_UPDATE_REFUSED", reason: CANARY }],
    ["path no string", { code: "FILE_TOO_LARGE", path: 3 }],
    ["count negativo", { code: "FILE_TOO_LARGE", count: -1 }],
    ["count no entero", { code: "FILE_TOO_LARGE", count: 1.5 }],
    ["no es objeto", "FILE_TOO_LARGE"],
    ["null", null],
  ])("rechaza %s", (_, input) => {
    expect(sanitizeWarning(input)).toBeNull();
  });
});

describe("sanitizeFindingDraft", () => {
  it("acepta un borrador válido sin cambiarlo", () => {
    const draft = draftOf(depEvent("high"));
    expect(sanitizeFindingDraft(draft, "dependency")).toEqual(draft);
  });

  it("descarta campos extra, también dentro de location y vuln", () => {
    const draft = {
      ...draftOf(misconfigEvent("low")),
      snippet: CANARY,
      secret: { redacted: CANARY, length: 1, inWorkingTree: true, occurrences: 1 },
      location: { kind: "file", path: "Dockerfile", line: 1, lineText: CANARY },
    };
    const out = sanitizeFindingDraft(draft, "misconfig");
    expect(out).toEqual({
      category: "misconfig",
      ruleId: "docker-latest-tag",
      severity: "low",
      title: "Image without tag",
      location: { kind: "file", path: "Dockerfile", line: 1 },
    });
    expect(JSON.stringify(out)).not.toContain(RAW_SECRET);
  });

  it.each([
    ["severidad en mayúsculas (OSV)", { severity: "CRITICAL" }],
    ["severidad desconocida", { severity: "moderate" }],
    ["categoría de otro escáner", { category: "misconfig" }],
    ["ruleId con espacios", { ruleId: `GHSA x ${CANARY}` }],
    ["title no string", { title: 42 }],
    ["location desconocida", { location: { kind: "url", href: "x" } }],
    [
      "package sin version",
      { location: { kind: "package", lockfile: "l", ecosystem: "npm", name: "n" } },
    ],
    ["vuln.aliases no es array", { vuln: { osvId: "GHSA-1", aliases: "CVE-1", url: "u" } }],
    ["dependency sin vuln", { vuln: undefined }],
  ])("rechaza %s", (_, over) => {
    expect(
      sanitizeFindingDraft({ ...draftOf(depEvent("high")), ...over }, "dependency"),
    ).toBeNull();
  });

  it.each([
    ["línea no entera", { kind: "file", path: "a", line: 1.5 }],
    ["línea 0", { kind: "file", path: "a", line: 0 }],
    ["path no string", { kind: "file", path: ["a"] }],
  ])("rechaza misconfig con %s", (_, location) => {
    expect(
      sanitizeFindingDraft({ ...draftOf(misconfigEvent()), location }, "misconfig"),
    ).toBeNull();
  });
});

describe("sanitizeSecretMatch", () => {
  const base = matchOf(
    secretEvent({ ordinal: 0, location: { path: "a", line: 1, column: 1, commit: "c1" } }),
  );

  it("acepta una coincidencia válida y descarta campos extra de location", () => {
    const out = sanitizeSecretMatch({
      ...base,
      location: { ...base.location, kind: "package", snippet: CANARY },
    });
    expect(out?.location).toEqual({ path: "a", line: 1, column: 1, commit: "c1" });
    expect(out?.value).toBe(base.value);
  });

  it.each([
    ["severidad desconocida", { severity: "CRITICAL" }],
    ["ruleId con mayúsculas o espacios", { ruleId: "Fake Rule" }],
    ["ruleId con NUL", { ruleId: "fake\u0000rule" }],
    ["publicPrefix que no es prefijo del valor", { publicPrefix: "ghp_" }],
    [
      "publicPrefix demasiado largo (casi todo el secreto)",
      { publicPrefix: RAW_SECRET.slice(0, 20) },
    ],
    ["value sin envolver en SecretValue", { value: RAW_SECRET }],
    ["ordinal no finito", { ordinal: Number.NaN }],
    ["inWorkingTree no booleano", { inWorkingTree: "yes" }],
  ])("rechaza %s", (_, over) => {
    expect(sanitizeSecretMatch({ ...base, ...over })).toBeNull();
  });

  it("acepta reglas sin prefijo (PEM)", () => {
    const pem = { ...base, publicPrefix: null, value: new SecretValue("material de clave") };
    expect(sanitizeSecretMatch(pem)).not.toBeNull();
  });
});
