// Dobles en memoria para probar runScan sin E/S. No se exportan desde index.ts.
import type { Baseline } from "../domain/baseline";
import type { Category } from "../domain/finding";
import type { RawSecretMatch } from "../domain/raw-secret-match";
import { SecretValue } from "../domain/secret-value";
import type { BaselineLoad, BaselineStore } from "../ports/baseline-store";
import type { Clock } from "../ports/clock";
import type { Hasher, RandomBytes } from "../ports/crypto";
import type { RepoDescription, RepoReader } from "../ports/repo-reader";
import type { FindingDraft, ScanContext, Scanner, ScannerEvent } from "../ports/scanner";

/**
 * FNV-1a con ocho semillas → 64 hex, la longitud de un SHA-256 real (sanitize-adapter
 * valida los fingerprints del baseline). Determinista y no reversible a efectos del test.
 * No sirve devolver los bytes en hex: eso sería el secreto codificado y los tests de
 * no filtrado no lo detectarían.
 */
export const fakeHash: Hasher = (bytes) => {
  const fnv = (seed: number) => {
    let h = seed >>> 0;
    for (const b of bytes) h = Math.imul(h ^ b, 0x01000193) >>> 0;
    return h.toString(16).padStart(8, "0");
  };
  return [
    0x811c9dc5, 0x01234567, 0x89abcdef, 0xdeadbeef, 0x0badf00d, 0x13579bdf, 0x2468ace0, 0x7f4a7c15,
  ]
    .map(fnv)
    .join("");
};

export const fixedRandom =
  (byte = 0x11): RandomBytes =>
  (n) =>
    new Uint8Array(n).fill(byte);

/** Devuelve los valores en orden; el último se repite. */
export function fakeClock(...ticks: number[]): Clock {
  let i = 0;
  return () => ticks[Math.min(i++, ticks.length - 1)] ?? 0;
}

export function fakeRepo(description?: RepoDescription): RepoReader {
  const d = description ?? {
    kind: "ok",
    info: { root: "/repo", headCommit: "c0ffee", shallow: false },
  };
  return { describe: async () => d };
}

export function memoryBaseline(initial: BaselineLoad | "throws" = { kind: "missing" }) {
  const saved: Baseline[] = [];
  const store: BaselineStore = {
    load: async () => {
      if (initial === "throws") throw new Error("EACCES: permission denied");
      return initial;
    },
    save: async (b) => {
      saved.push(b);
    },
  };
  return { store, saved };
}

export interface FakeScannerOptions {
  /** Lanza este error después de emitir todos los eventos. */
  throwAfter?: Error;
}

/** Escáner que emite los eventos dados y registra cuántas veces se invocó. */
export function fakeScanner(
  category: Category,
  events: readonly ScannerEvent[],
  opts: FakeScannerOptions = {},
) {
  const calls: ScanContext[] = [];
  const scanner: Scanner = {
    category,
    async *scan(ctx) {
      calls.push(ctx);
      for (const e of events) {
        // Cede el turno: simula E/S y permite que los escáneres se intercalen.
        await Promise.resolve();
        yield e;
      }
      if (opts.throwAfter) throw opts.throwAfter;
    },
  };
  return { scanner, calls };
}

// --- Constructores de eventos -------------------------------------------------------------

export const RAW_SECRET = "not-a-real-token-0123456789abcdef";

export function secretEvent(
  over: Partial<RawSecretMatch> & Pick<RawSecretMatch, "ordinal">,
): ScannerEvent {
  return {
    type: "secret",
    match: {
      ruleId: "fake-token",
      severity: "high",
      title: "Fake token",
      publicPrefix: "not-",
      kindLabel: "fake token",
      value: new SecretValue(RAW_SECRET),
      location: { path: "config.txt", line: 3, column: 7 },
      inWorkingTree: false,
      ...over,
    },
  };
}

export function depEvent(severity: FindingDraft["severity"] = "high"): ScannerEvent {
  return {
    type: "finding",
    anchor: "",
    finding: {
      category: "dependency",
      ruleId: "GHSA-fake-0001",
      severity,
      title: "Vulnerable lodash",
      location: {
        kind: "package",
        lockfile: "pnpm-lock.yaml",
        ecosystem: "npm",
        name: "lodash",
        version: "4.17.20",
      },
      vuln: { osvId: "GHSA-fake-0001", aliases: [], url: "https://osv.dev/GHSA-fake-0001" },
    },
  };
}

export function misconfigEvent(
  severity: FindingDraft["severity"] = "low",
  category: Category = "misconfig",
): ScannerEvent {
  return {
    type: "finding",
    anchor: "FROM#0",
    finding: {
      category,
      ruleId: "docker-latest-tag",
      severity,
      title: "Image without tag",
      location: { kind: "file", path: "Dockerfile", line: 1 },
    },
  };
}
