import { describe, expect, it } from "vitest";
import type { Baseline } from "../domain/baseline";
import type { Scanner, ScannerEvent } from "../ports/scanner";
import {
  RAW_SECRET,
  depEvent,
  fakeClock,
  fakeHash,
  fakeRepo,
  fakeScanner,
  fixedRandom,
  memoryBaseline,
  misconfigEvent,
  secretEvent,
} from "../testing/fakes";
import { runScan, type RunScanDeps, type RunScanOptions, type RunScanOutcome } from "./run-scan";

const historyLeak = secretEvent({
  ordinal: 0,
  location: { path: "old.txt", line: 1, column: 1, commit: "c1" },
});
const treeLeak = secretEvent({ ordinal: 5, inWorkingTree: true });

function setup(over: Partial<RunScanDeps> = {}, opts: Partial<RunScanOptions> = {}) {
  const secrets = fakeScanner("secret", [historyLeak, treeLeak]);
  const deps = fakeScanner("dependency", [depEvent("high")]);
  const misconfig = fakeScanner("misconfig", [
    misconfigEvent("low"),
    { type: "warning", warning: { code: "FILE_TOO_LARGE", path: "big.bin" } },
  ]);
  const baseline = memoryBaseline();
  const d: RunScanDeps = {
    repo: fakeRepo(),
    scanners: [secrets.scanner, deps.scanner, misconfig.scanner],
    baseline: baseline.store,
    hash: fakeHash,
    random: fixedRandom(),
    clock: fakeClock(1000, 1250),
    ...over,
  };
  const o: RunScanOptions = {
    failOn: "high",
    history: true,
    skipped: [],
    updateBaseline: false,
    toolVersion: "0.0.0-test",
    rulesetVersion: "rs-test",
    ...opts,
  };
  return { d, o, saved: baseline.saved, calls: { secrets, deps, misconfig } };
}

function ok(outcome: RunScanOutcome) {
  if (outcome.kind !== "ok") throw new Error(`esperaba ok, llegó ${outcome.kind}`);
  return outcome;
}

function expectNoLeak(outcome: RunScanOutcome, saved: Baseline[] = []) {
  expect(JSON.stringify(outcome)).not.toContain(RAW_SECRET);
  expect(JSON.stringify(saved)).not.toContain(RAW_SECRET);
}

describe("runScan", () => {
  it("camino feliz: resultado ordenado, deduplicado y con metadatos", async () => {
    const { d, o } = setup();
    const out = ok(await runScan(d, o));

    expect(out.exitCode).toBe(1);
    expect(out.result).toMatchObject({
      schemaVersion: 1,
      tool: { name: "repoguard", version: "0.0.0-test", rulesetVersion: "rs-test" },
      target: { root: "/repo", headCommit: "c0ffee", shallow: false },
      durationMs: 250,
      warnings: [],
      categories: {
        secret: { status: "complete", warnings: [] },
        dependency: { status: "complete", warnings: [] },
        misconfig: { status: "complete", warnings: [{ code: "FILE_TOO_LARGE", path: "big.bin" }] },
      },
    });
    expect(out.result.findings.map((x) => x.category)).toEqual([
      "secret",
      "dependency",
      "misconfig",
    ]);
    expect(out.result.findings[0]).toMatchObject({
      location: { kind: "file", path: "old.txt", commit: "c1" },
      secret: { redacted: "not-****", inWorkingTree: true, occurrences: 2 },
      suppressed: false,
    });
    expectNoLeak(out);
  });

  it("pasa history y el repo a los escáneres", async () => {
    const { d, o, calls } = setup({}, { history: false });
    await runScan(d, o);
    expect(calls.secrets.calls).toEqual([
      { repo: { root: "/repo", headCommit: "c0ffee", shallow: false }, history: false },
    ]);
  });

  describe("aislamiento de fallos (§2.2)", () => {
    it("un escáner que lanza conserva lo emitido y marca su categoría incompleta", async () => {
      const deps = fakeScanner("dependency", [depEvent("high")], { throwAfter: new Error("boom") });
      const { d, o, calls } = setup();
      const scanners = [calls.secrets.scanner, deps.scanner, calls.misconfig.scanner];
      const out = ok(await runScan({ ...d, scanners }, o));

      expect(out.result.categories.dependency).toEqual({
        status: "incomplete",
        warnings: [{ code: "SCANNER_FAILED" }],
      });
      expect(out.result.categories.secret.status).toBe("complete");
      expect(out.result.findings.some((x) => x.category === "dependency")).toBe(true);
      expect(out.exitCode).toBe(1);
    });

    it("incompleto sin hallazgos ≥ umbral da exit 2", async () => {
      const failing = fakeScanner("misconfig", [misconfigEvent("low")], {
        throwAfter: new Error("x"),
      });
      const { d, o } = setup({ scanners: [failing.scanner] });
      expect(ok(await runScan(d, o)).exitCode).toBe(2);
    });

    it("el mensaje de la excepción nunca llega a la salida", async () => {
      const leaky = fakeScanner("secret", [], {
        throwAfter: new Error(`regex falló en la línea: TOKEN=${RAW_SECRET}`),
      });
      const { d, o } = setup({ scanners: [leaky.scanner] });
      expectNoLeak(await runScan(d, o));
    });

    it("un hallazgo de otra categoría es una violación de contrato", async () => {
      const liar = fakeScanner("misconfig", [misconfigEvent("critical", "dependency")]);
      const { d, o } = setup({ scanners: [liar.scanner] });
      const out = ok(await runScan(d, o));
      expect(out.result.findings).toEqual([]);
      expect(out.result.categories.misconfig).toEqual({
        status: "incomplete",
        warnings: [{ code: "SCANNER_CONTRACT_VIOLATION" }],
      });
    });

    it("un secreto emitido por un escáner que no es de secretos es una violación", async () => {
      const liar = fakeScanner("misconfig", [treeLeak]);
      const { d, o } = setup({ scanners: [liar.scanner] });
      const out = ok(await runScan(d, o));
      expect(out.result.findings).toEqual([]);
      expect(out.result.categories.misconfig.warnings).toEqual([
        { code: "SCANNER_CONTRACT_VIOLATION" },
      ]);
    });

    it("un borrador con forma incoherente es una violación", async () => {
      const bad = depEvent();
      if (bad.type === "finding") delete bad.finding.vuln;
      const liar = fakeScanner("dependency", [bad]);
      const { d, o } = setup({ scanners: [liar.scanner] });
      expect(ok(await runScan(d, o)).result.categories.dependency.status).toBe("incomplete");
    });
  });

  describe("estado de las categorías", () => {
    it("una categoría en skipped no invoca su escáner", async () => {
      const { d, o, calls } = setup({}, { skipped: ["dependency"] });
      const out = ok(await runScan(d, o));
      expect(calls.deps.calls).toHaveLength(0);
      expect(out.result.categories.dependency).toEqual({ status: "skipped", warnings: [] });
      expect(out.result.findings.some((x) => x.category === "dependency")).toBe(false);
    });

    it("status incomplete emitido por el escáner (OSV caído)", async () => {
      const osvDown = fakeScanner("dependency", [
        { type: "warning", warning: { code: "OSV_UNAVAILABLE" } },
        { type: "status", status: "incomplete" },
      ]);
      const onlyDeps = setup({ scanners: [osvDown.scanner] });
      const out = ok(await runScan(onlyDeps.d, onlyDeps.o));
      expect(out.result.categories.dependency).toEqual({
        status: "incomplete",
        warnings: [{ code: "OSV_UNAVAILABLE" }],
      });
      expect(out.exitCode).toBe(2);

      const withSecret = setup();
      const scanners = [withSecret.calls.secrets.scanner, osvDown.scanner];
      expect(ok(await runScan({ ...withSecret.d, scanners }, withSecret.o)).exitCode).toBe(1);
    });

    it("clon superficial genera un aviso global", async () => {
      const repo = fakeRepo({ kind: "ok", info: { root: "/repo", shallow: true } });
      const { d, o } = setup({ repo });
      const out = ok(await runScan(d, o));
      expect(out.result.warnings).toEqual([{ code: "SHALLOW_CLONE" }]);
      expect(out.result.target).toEqual({ root: "/repo", shallow: true });
    });

    it("repo inválido es fatal y no ejecuta escáneres", async () => {
      const repo = fakeRepo({ kind: "fatal", code: "NOT_A_GIT_REPO" });
      const { d, o, calls } = setup({ repo });
      expect(await runScan(d, o)).toEqual({ kind: "fatal", code: "NOT_A_GIT_REPO", exitCode: 2 });
      expect(calls.secrets.calls).toHaveLength(0);
    });
  });

  describe("baseline", () => {
    async function idsFromFirstRun() {
      const { d, o } = setup({ random: fixedRandom(0x22) });
      return ok(await runScan(d, o)).result.findings.map((x) => x.id);
    }

    it("un baseline válido suprime por id y usa su sal", async () => {
      const salt = "22".repeat(32);
      const entries = (await idsFromFirstRun()).map((id) => ({
        fingerprint: id,
        ruleId: "r",
        note: "",
      }));
      const baseline = memoryBaseline({ kind: "valid", baseline: { version: 1, salt, entries } });
      // random distinto: si runScan no usara la sal del baseline, los ids no coincidirían.
      const { d, o } = setup({ baseline: baseline.store, random: fixedRandom(0x99) });
      const out = ok(await runScan(d, o));
      expect(out.result.findings.every((x) => x.suppressed)).toBe(true);
      expect(out.exitCode).toBe(0);
    });

    it("sin baseline, la sal es aleatoria por ejecución", async () => {
      const a = setup({ random: fixedRandom(0x01) });
      const b = setup({ random: fixedRandom(0x02) });
      const idA = ok(await runScan(a.d, a.o)).result.findings[0]?.id;
      const idB = ok(await runScan(b.d, b.o)).result.findings[0]?.id;
      expect(idA).not.toBe(idB);
    });

    it.each([
      ["invalid", { kind: "invalid" } as const],
      ["que lanza al cargar", "throws" as const],
    ])("un baseline %s avisa y no suprime nada", async (_, load) => {
      const baseline = memoryBaseline(load);
      const { d, o } = setup({ baseline: baseline.store });
      const out = ok(await runScan(d, o));
      expect(out.result.warnings).toEqual([{ code: "BASELINE_INVALID" }]);
      expect(out.result.findings.some((x) => x.suppressed)).toBe(false);
      expect(JSON.stringify(out)).not.toContain("EACCES");
    });
  });

  describe("--update-baseline (§2.5)", () => {
    it("con scan completo guarda una vez, suprime todo y da exit 0", async () => {
      const { d, o, saved } = setup({}, { updateBaseline: true });
      const out = ok(await runScan(d, o));
      expect(saved).toHaveLength(1);
      expect(saved[0]?.salt).toBe("11".repeat(32));
      expect(saved[0]?.entries).toHaveLength(3);
      expect(out.result.findings.every((x) => x.suppressed)).toBe(true);
      expect(out.exitCode).toBe(0);
      expectNoLeak(out, saved);
    });

    it("con scan parcial no guarda, avisa y da exit 2 aunque haya hallazgos ≥ umbral", async () => {
      const { d, o, saved } = setup({}, { updateBaseline: true, skipped: ["dependency"] });
      const out = ok(await runScan(d, o));
      expect(saved).toHaveLength(0);
      expect(out.result.warnings).toEqual([
        { code: "BASELINE_UPDATE_REFUSED", reason: "partial-scan" },
      ]);
      expect(out.result.findings.some((x) => x.suppressed)).toBe(false);
      expect(out.exitCode).toBe(2);
    });

    it("con baseline inválido no guarda y explica el motivo", async () => {
      const baseline = memoryBaseline({ kind: "invalid" });
      const { d, o } = setup({ baseline: baseline.store }, { updateBaseline: true });
      const out = ok(await runScan(d, o));
      expect(baseline.saved).toHaveLength(0);
      expect(out.result.warnings).toEqual([
        { code: "BASELINE_INVALID" },
        { code: "BASELINE_UPDATE_REFUSED", reason: "invalid-baseline" },
      ]);
      expect(out.exitCode).toBe(2);
    });
  });

  it("determinista: el orden de emisión y de los escáneres no cambia el resultado", async () => {
    const a = setup();
    const reversed: Scanner[] = [
      fakeScanner("misconfig", [
        { type: "warning", warning: { code: "FILE_TOO_LARGE", path: "big.bin" } },
        misconfigEvent("low"),
      ]).scanner,
      fakeScanner("dependency", [depEvent("high")]).scanner,
      fakeScanner("secret", [treeLeak, historyLeak]).scanner,
    ];
    const b = setup({ scanners: reversed });
    const outA = ok(await runScan(a.d, a.o));
    const outB = ok(await runScan(b.d, b.o));
    expect(JSON.stringify(outB.result.findings)).toBe(JSON.stringify(outA.result.findings));
  });
});

// Escenarios de la revisión de seguridad: un escáner o adaptador con un bug no puede
// saltarse el gate ni colar texto en la salida.
describe("runScan: validación en runtime", () => {
  const CANARY = `TOKEN=${RAW_SECRET}`;
  const untyped = (e: unknown) => e as ScannerEvent;

  it("una severidad desconocida (OSV en mayúsculas) no deja pasar el gate", async () => {
    const dep = depEvent("high");
    if (dep.type === "finding") (dep.finding as { severity: string }).severity = "CRITICAL";
    const { d, o } = setup(
      { scanners: [fakeScanner("dependency", [dep]).scanner] },
      { failOn: "low" },
    );
    const out = ok(await runScan(d, o));
    expect(out.result.categories.dependency).toEqual({
      status: "incomplete",
      warnings: [{ code: "SCANNER_CONTRACT_VIOLATION" }],
    });
    expect(out.exitCode).toBe(2);
  });

  it("los campos extra de un hallazgo no llegan a la salida", async () => {
    const event = misconfigEvent("low");
    if (event.type === "finding") Object.assign(event.finding, { snippet: CANARY });
    const { d, o } = setup({ scanners: [fakeScanner("misconfig", [event]).scanner] });
    const out = ok(await runScan(d, o));
    expect(out.result.findings).toHaveLength(1);
    expectNoLeak(out);
  });

  it("un aviso con texto libre pierde el campo; con código desconocido es violación", async () => {
    const scanner = fakeScanner("misconfig", [
      untyped({ type: "warning", warning: { code: "FILE_TOO_LARGE", message: CANARY } }),
      untyped({ type: "warning", warning: { code: CANARY } }),
    ]).scanner;
    const { d, o } = setup({ scanners: [scanner] });
    const out = ok(await runScan(d, o));
    expect(out.result.categories.misconfig.warnings).toEqual([
      { code: "FILE_TOO_LARGE" },
      { code: "SCANNER_CONTRACT_VIOLATION" },
    ]);
    expectNoLeak(out);
  });

  it("un publicPrefix que es casi todo el secreto es violación y no se filtra", async () => {
    const leak = secretEvent({ ordinal: 0, publicPrefix: RAW_SECRET.slice(0, 30) });
    const { d, o } = setup({ scanners: [fakeScanner("secret", [leak]).scanner] });
    const out = ok(await runScan(d, o));
    expect(out.result.categories.secret.warnings).toEqual([{ code: "SCANNER_CONTRACT_VIOLATION" }]);
    expectNoLeak(out);
  });

  it("una sal en mayúsculas se normaliza y sigue suprimiendo", async () => {
    const first = setup({ random: fixedRandom(0xab) });
    const ids = ok(await runScan(first.d, first.o)).result.findings.map((x) => x.id);
    const entries = ids.map((id) => ({ fingerprint: id, ruleId: "r", note: "" }));
    const baseline = memoryBaseline({
      kind: "valid",
      baseline: { version: 1, salt: "AB".repeat(32), entries },
    });
    const { d, o } = setup({ baseline: baseline.store, random: fixedRandom(0x01) });
    const out = ok(await runScan(d, o));
    expect(out.result.findings.every((x) => x.suppressed)).toBe(true);
    expect(out.result.categories.secret.status).toBe("complete");
  });

  it("una sal que no es hex de 32 bytes invalida el baseline, no el escáner de secretos", async () => {
    const baseline = memoryBaseline({
      kind: "valid",
      baseline: { version: 1, salt: "zz".repeat(32), entries: [] },
    });
    const { d, o } = setup({ baseline: baseline.store });
    const out = ok(await runScan(d, o));
    expect(out.result.warnings).toEqual([{ code: "BASELINE_INVALID" }]);
    expect(out.result.categories.secret.status).toBe("complete");
    expect(out.result.findings.some((x) => x.category === "secret")).toBe(true);
  });

  it("si falla el guardado del baseline se devuelve el informe con exit 2", async () => {
    const baseline = memoryBaseline();
    baseline.store.save = async () => {
      throw new Error(`ENOSPC ${CANARY}`);
    };
    const { d, o } = setup({ baseline: baseline.store }, { updateBaseline: true });
    const out = ok(await runScan(d, o));
    expect(out.result.warnings).toEqual([{ code: "BASELINE_SAVE_FAILED" }]);
    expect(out.result.findings.some((x) => x.suppressed)).toBe(false);
    expect(out.exitCode).toBe(2);
    expectNoLeak(out);
  });

  it("si describe() lanza, es fatal REPO_ERROR sin el mensaje", async () => {
    const repo = {
      describe: async () => {
        throw new Error(CANARY);
      },
    };
    const { d, o } = setup({ repo });
    const out = await runScan(d, o);
    expect(out).toEqual({ kind: "fatal", code: "REPO_ERROR", exitCode: 2 });
  });

  it("target solo copia root, headCommit y shallow", async () => {
    const info = { root: "/repo", shallow: false, gitDir: CANARY };
    const { d, o } = setup({ repo: fakeRepo({ kind: "ok", info }) });
    expect(ok(await runScan(d, o)).result.target).toEqual({ root: "/repo", shallow: false });
  });
});
