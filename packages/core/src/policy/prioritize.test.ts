import { describe, expect, it } from "vitest";
import { prioritize } from "./prioritize";
import { f } from "../testing/findings";

const ids = (xs: { id: string }[]) => xs.map((x) => x.id);

describe("prioritize (mvp §2.6)", () => {
  it("severidad desc", () => {
    expect(
      ids(prioritize([f("l", "low"), f("c", "critical"), f("m", "medium"), f("h", "high")])),
    ).toEqual(["c", "h", "m", "l"]);
  });

  it("a igual severidad: secret > dependency > misconfig", () => {
    const xs = [
      f("mis", "high", "misconfig"),
      f("dep", "high", "dependency"),
      f("sec", "high", "secret"),
    ];
    expect(ids(prioritize(xs))).toEqual(["sec", "dep", "mis"]);
  });

  it("a igual severidad y categoría: inWorkingTree primero", () => {
    const xs = [
      f("hist", "high", "secret", { path: "a" }),
      f("tree", "high", "secret", { path: "z", inWorkingTree: true }),
    ];
    expect(ids(prioritize(xs))).toEqual(["tree", "hist"]);
  });

  it("después por ruta y luego por línea", () => {
    const xs = [
      f("b1", "low", "misconfig", { path: "b", line: 1 }),
      f("a10", "low", "misconfig", { path: "a", line: 10 }),
      f("a2", "low", "misconfig", { path: "a", line: 2 }),
    ];
    expect(ids(prioritize(xs))).toEqual(["a2", "a10", "b1"]);
  });

  it("deps sin línea usan el lockfile como ruta", () => {
    const xs = [
      f("y", "high", "dependency", { path: "y.lock" }),
      f("x", "high", "dependency", { path: "x.lock" }),
    ];
    expect(ids(prioritize(xs))).toEqual(["x", "y"]);
  });

  it("ordena rutas por código, como git, y no según el idioma del sistema", () => {
    const xs = [
      f("lower", "low", "misconfig", { path: "a.yml" }),
      f("upper", "low", "misconfig", { path: "B.yml" }),
      f("umlaut", "low", "misconfig", { path: "ä.yml" }),
      f("z", "low", "misconfig", { path: "z.yml" }),
    ];
    expect(ids(prioritize(xs))).toEqual(["upper", "lower", "z", "umlaut"]);
  });

  it("si empata en todo, desempata por id (no por orden de emisión)", () => {
    // Dos vulnerabilidades del mismo lockfile: sin línea, empatan en todos los criterios.
    const vulnB = f("id-b", "high", "dependency", { path: "pnpm-lock.yaml" });
    const vulnA = f("id-a", "high", "dependency", { path: "pnpm-lock.yaml" });
    expect(ids(prioritize([vulnB, vulnA]))).toEqual(["id-a", "id-b"]);
    expect(ids(prioritize([vulnA, vulnB]))).toEqual(["id-a", "id-b"]);
  });

  it("no muta la entrada y es estable ante permutaciones", () => {
    const xs = [f("1", "low"), f("2", "high", "misconfig"), f("3", "high")];
    const copy = [...xs];
    const out = prioritize(xs);
    expect(xs).toEqual(copy);
    expect(prioritize([...xs].reverse())).toEqual(out);
  });
});
