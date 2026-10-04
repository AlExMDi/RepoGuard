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

const base = matchOf(
  secretEvent({ ordinal: 0, location: { path: "a", line: 1, column: 1, commit: "c1" } }),
);

describe("sanitizeSecretMatch", () => {
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

// Segunda revisión de seguridad: lecturas dobles (M-1), texto con el secreto (M-3),
// prefijo que deja poco oculto (B-2) y tamaños sin límite (B-5).
describe("sanitize-event: segunda revisión", () => {
  /** Getter que devuelve `first` en la primera lectura y `then` en las siguientes. */
  function flipping<T extends object>(obj: T, key: string, first: unknown, then: unknown): T {
    let reads = 0;
    Object.defineProperty(obj, key, {
      enumerable: true,
      get: () => (reads++ === 0 ? first : then),
    });
    return obj;
  }

  describe("cada campo se lee una sola vez (M-1)", () => {
    it("warning.code", () => {
      const w = flipping({}, "code", "FILE_TOO_LARGE", CANARY);
      expect(sanitizeWarning(w)).toEqual({ code: "FILE_TOO_LARGE" });
    });

    it("location.path de un misconfig", () => {
      const location = flipping({ kind: "file" }, "path", "Dockerfile", { snippet: CANARY });
      const out = sanitizeFindingDraft({ ...draftOf(misconfigEvent()), location }, "misconfig");
      expect(out?.location).toEqual({ kind: "file", path: "Dockerfile" });
    });

    it("vuln.osvId y vuln.aliases", () => {
      const vuln = flipping({ url: "https://osv.dev/x", aliases: [] }, "osvId", "GHSA-1", {
        x: CANARY,
      });
      flipping(vuln, "aliases", ["CVE-1"], [CANARY]);
      const out = sanitizeFindingDraft({ ...draftOf(depEvent()), vuln }, "dependency");
      expect(out?.vuln).toEqual({ osvId: "GHSA-1", aliases: ["CVE-1"], url: "https://osv.dev/x" });
    });

    it("value de un secreto: se usa el SecretValue que se validó", () => {
      const real = new SecretValue(RAW_SECRET);
      const match = flipping({ ...base }, "value", real, new SecretValue("x"));
      expect(sanitizeSecretMatch(match)?.value).toBe(real);
    });
  });

  describe("ningún texto contiene el secreto (M-3)", () => {
    it.each([
      ["title", { title: `Token: ${RAW_SECRET}` }],
      ["kindLabel", { kindLabel: `line: ${RAW_SECRET}` }],
      ["location.path", { location: { path: `${RAW_SECRET}.txt`, line: 1, column: 1 } }],
      ["location.commit", { location: { path: "a", line: 1, column: 1, commit: RAW_SECRET } }],
    ])("rechaza el secreto dentro de %s", (_, over) => {
      expect(sanitizeSecretMatch({ ...base, ...over })).toBeNull();
    });
  });

  describe("el prefijo público deja oculto lo suficiente (B-2)", () => {
    it("rechaza menos de 16 caracteres ocultos", () => {
      const value = new SecretValue("not-" + "a".repeat(15));
      expect(sanitizeSecretMatch({ ...base, value })).toBeNull();
    });

    it("acepta 16 caracteres ocultos", () => {
      const value = new SecretValue("not-" + "a".repeat(16));
      expect(sanitizeSecretMatch({ ...base, value })).not.toBeNull();
    });

    it("sin prefijo (PEM) exige también 16 caracteres", () => {
      const value = new SecretValue("a".repeat(15));
      expect(sanitizeSecretMatch({ ...base, publicPrefix: null, value })).toBeNull();
    });
  });

  describe("límites de tamaño (B-5)", () => {
    const dep = () => draftOf(depEvent());
    const withVuln = (over: object) => ({ ...dep(), vuln: { ...dep().vuln, ...over } });

    it("rechaza aliases con huecos", () => {
      // eslint-disable-next-line no-sparse-arrays -- es justo el caso a probar
      expect(sanitizeFindingDraft(withVuln({ aliases: [, "CVE-1"] }), "dependency")).toBeNull();
    });

    it("rechaza más de 100 aliases", () => {
      const aliases = Array.from({ length: 101 }, (_, i) => `CVE-${i}`);
      expect(sanitizeFindingDraft(withVuln({ aliases }), "dependency")).toBeNull();
    });

    it("rechaza un array disperso enorme sin recorrerlo", () => {
      const aliases: string[] = [];
      aliases.length = 50_000_000;
      const started = Date.now();
      expect(sanitizeFindingDraft(withVuln({ aliases }), "dependency")).toBeNull();
      expect(Date.now() - started).toBeLessThan(50);
    });

    it("rechaza un title de más de 512 caracteres", () => {
      expect(sanitizeFindingDraft({ ...dep(), title: "t".repeat(513) }, "dependency")).toBeNull();
    });

    it("rechaza una ruta de más de 4096 caracteres", () => {
      const location = { kind: "file", path: "a".repeat(4097) };
      const draft = { ...draftOf(misconfigEvent()), location };
      expect(sanitizeFindingDraft(draft, "misconfig")).toBeNull();
    });
  });
});
