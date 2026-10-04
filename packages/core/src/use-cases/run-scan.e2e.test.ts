// Escenario known-repo en memoria (spec finding-runscan §8.3): recorre scan, negativa a
// actualizar el baseline, actualización y segundo scan suprimido.
import { describe, expect, it } from "vitest";
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
  secretEvent,
} from "../testing/fakes";
import { runScan, type RunScanDeps, type RunScanOptions } from "./run-scan";

// El mismo secreto añadido en c1, copiado en c2 y c3, y aún presente en el árbol.
const secretEvents: ScannerEvent[] = [
  secretEvent({ ordinal: 2, location: { path: "deploy.sh", line: 4, column: 9, commit: "c3" } }),
  secretEvent({ ordinal: 0, location: { path: "config.txt", line: 3, column: 7, commit: "c1" } }),
  secretEvent({ ordinal: 1, location: { path: "config.txt", line: 3, column: 7, commit: "c2" } }),
  secretEvent({
    ordinal: 9,
    location: { path: "deploy.sh", line: 4, column: 9 },
    inWorkingTree: true,
  }),
];

const envCommitted: ScannerEvent = {
  type: "finding",
  anchor: "",
  finding: {
    category: "misconfig",
    ruleId: "env-file-committed",
    severity: "high",
    title: ".env file committed",
    location: { kind: "file", path: ".env" },
  },
};

function scanners(depsComplete: boolean): Scanner[] {
  const depsEvents: ScannerEvent[] = depsComplete
    ? [depEvent("high")]
    : [
        { type: "warning", warning: { code: "OSV_UNAVAILABLE" } },
        { type: "status", status: "incomplete" },
      ];
  return [
    fakeScanner("secret", secretEvents).scanner,
    fakeScanner("dependency", depsEvents).scanner,
    fakeScanner("misconfig", [envCommitted]).scanner,
  ];
}

const opts: RunScanOptions = {
  failOn: "high",
  history: true,
  skipped: [],
  updateBaseline: false,
  toolVersion: "0.1.0",
  rulesetVersion: "rs-1",
};

function deps(over: Partial<RunScanDeps>): RunScanDeps {
  return {
    repo: fakeRepo(),
    scanners: scanners(false),
    baseline: memoryBaseline().store,
    hash: fakeHash,
    random: fixedRandom(),
    clock: fakeClock(0, 42),
    ...over,
  };
}

describe("runScan e2e (known-repo en memoria)", () => {
  it("OSV caído: exit 1 por el secreto y resultado exacto", async () => {
    const out = await runScan(deps({}), opts);
    expect(out.exitCode).toBe(1);
    expect(JSON.stringify(out)).not.toContain(RAW_SECRET);
    expect(out).toMatchInlineSnapshot(`
      {
        "exitCode": 1,
        "kind": "ok",
        "result": {
          "categories": {
            "dependency": {
              "status": "incomplete",
              "warnings": [
                {
                  "code": "OSV_UNAVAILABLE",
                },
              ],
            },
            "misconfig": {
              "status": "complete",
              "warnings": [],
            },
            "secret": {
              "status": "complete",
              "warnings": [],
            },
          },
          "durationMs": 42,
          "findings": [
            {
              "category": "secret",
              "id": "53295dfbc04ffad9",
              "location": {
                "column": 7,
                "commit": "c1",
                "kind": "file",
                "line": 3,
                "path": "config.txt",
              },
              "ruleId": "fake-token",
              "secret": {
                "inWorkingTree": true,
                "length": 33,
                "occurrences": 4,
                "redacted": "not-****",
              },
              "severity": "high",
              "suppressed": false,
              "title": "Fake token",
            },
            {
              "category": "misconfig",
              "id": "0c1450c6115530f4",
              "location": {
                "kind": "file",
                "path": ".env",
              },
              "ruleId": "env-file-committed",
              "severity": "high",
              "suppressed": false,
              "title": ".env file committed",
            },
          ],
          "schemaVersion": 1,
          "target": {
            "headCommit": "c0ffee",
            "root": "/repo",
            "shallow": false,
          },
          "tool": {
            "name": "repoguard",
            "rulesetVersion": "rs-1",
            "version": "0.1.0",
          },
          "warnings": [],
        },
      }
    `);
  });

  it("con OSV caído, --update-baseline se niega y no escribe", async () => {
    const baseline = memoryBaseline();
    const out = await runScan(deps({ baseline: baseline.store }), {
      ...opts,
      updateBaseline: true,
    });
    expect(out.exitCode).toBe(2);
    expect(baseline.saved).toEqual([]);
  });

  it("con OSV disponible: actualiza el baseline y el siguiente scan da exit 0", async () => {
    const first = memoryBaseline();
    const update = await runScan(deps({ baseline: first.store, scanners: scanners(true) }), {
      ...opts,
      updateBaseline: true,
    });
    expect(update.exitCode).toBe(0);
    expect(first.saved).toHaveLength(1);
    const saved = first.saved[0];
    if (!saved) throw new Error("no se guardó el baseline");
    expect(JSON.stringify(saved)).not.toContain(RAW_SECRET);

    // Segundo scan: otra sal aleatoria, pero debe usar la del baseline guardado.
    const second = await runScan(
      deps({
        baseline: memoryBaseline({ kind: "valid", baseline: saved }).store,
        scanners: scanners(true),
        random: fixedRandom(0x77),
      }),
      opts,
    );
    if (second.kind !== "ok") throw new Error("esperaba ok");
    expect(second.exitCode).toBe(0);
    expect(second.result.findings).toHaveLength(3);
    expect(second.result.findings.every((x) => x.suppressed)).toBe(true);
  });
});
