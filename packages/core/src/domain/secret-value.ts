const REDACTED = "[REDACTED]";
/** Por encima de esto, hasPrefix serviría para adivinar el secreto carácter a carácter. */
const MAX_PREFIX_CHECK = 12;

/**
 * Valor de un secreto en claro, opaco frente a serialización accidental:
 * String(), plantillas, JSON.stringify y util.inspect devuelven "[REDACTED]".
 * Solo policy/fingerprint y scanner-secrets pueden llamar a unsafeReveal (ADR 0008).
 *
 * Los métodos estáticos leen el campo privado `#value` directamente: un Proxy o un objeto
 * imitado no lo tienen, y una subclase no puede redefinirlos sobre la instancia.
 */
export class SecretValue {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  /** Marca privada: false para Proxies, objetos con el mismo prototipo o imitaciones. */
  static isGenuine(x: unknown): x is SecretValue {
    return typeof x === "object" && x !== null && #value in x;
  }

  /** Longitud real: el getter `length` de una subclase podría devolver cualquier cosa. */
  static lengthOf(v: SecretValue): number {
    return v.#value.length;
  }

  /** Valida el prefijo público de una regla. Solo policy/sanitize-event (ADR 0008). */
  static hasPrefix(v: SecretValue, prefix: string): boolean {
    return prefix.length <= MAX_PREFIX_CHECK && v.#value.startsWith(prefix);
  }

  /** ¿Aparece el valor completo en este texto? Solo policy/sanitize-event (ADR 0008). */
  static occursIn(v: SecretValue, text: string): boolean {
    return v.#value.length > 0 && text.includes(v.#value);
  }

  get length(): number {
    return this.#value.length;
  }

  unsafeReveal(): string {
    return this.#value;
  }

  toString(): string {
    return REDACTED;
  }

  toJSON(): string {
    return REDACTED;
  }

  valueOf(): string {
    return REDACTED;
  }

  // Symbol.for evita importar node:util: core no depende de Node.
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return REDACTED;
  }
}
