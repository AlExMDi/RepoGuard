import type { Baseline } from "../domain/baseline";

/** `invalid`: el fichero existe pero no pasa la validación de esquema (entrada no confiable). */
export type BaselineLoad =
  | { kind: "missing" }
  | { kind: "invalid" }
  | { kind: "valid"; baseline: Baseline };

export interface BaselineStore {
  load(): Promise<BaselineLoad>;
  save(baseline: Baseline): Promise<void>;
}
