// Comprobaciones de runtime compartidas por la validación de escáneres (sanitize-event) y
// de adaptadores (sanitize-adapter). Todo lo que viene de fuera de core es `unknown`.

/** Rutas, URLs, nombres y versiones. */
export const MAX_FIELD = 4096;

export type Obj = Record<string, unknown>;

export const isObj = (v: unknown): v is Obj =>
  typeof v === "object" && v !== null && !Array.isArray(v);
export const isStr = (v: unknown): v is string => typeof v === "string";
export const strMax =
  (max: number) =>
  (v: unknown): v is string =>
    isStr(v) && v.length <= max;
export const isField = strMax(MAX_FIELD);
export const isOneOf = <T extends string>(list: readonly T[], v: unknown): v is T =>
  isStr(v) && (list as readonly string[]).includes(v);

/** `undefined` si el campo no está; null si está y no es válido. */
export function optional<T>(v: unknown, ok: (x: unknown) => x is T): T | undefined | null {
  if (v === undefined) return undefined;
  return ok(v) ? v : null;
}

/**
 * Copia acotada de un array no confiable: lee `length` una vez, rechaza antes de recorrer
 * si es enorme (un array disperso de millones de huecos agotaría la memoria) y lee cada
 * posición una sola vez. Los huecos quedan como `undefined` y no pasan la validación.
 */
export function boundedCopy(input: unknown, max: number): unknown[] | null {
  if (!Array.isArray(input)) return null;
  const n: unknown = input.length;
  if (!Number.isInteger(n) || (n as number) > max) return null;
  return Array.from({ length: n as number }, (_, i) => input[i] as unknown);
}
