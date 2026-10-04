const REDACTED = "[REDACTED]";

/**
 * Valor de un secreto en claro, opaco frente a serialización accidental:
 * String(), plantillas, JSON.stringify y util.inspect devuelven "[REDACTED]".
 * Solo policy/fingerprint y scanner-secrets pueden llamar a unsafeReveal (ADR 0008).
 */
export class SecretValue {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  get length(): number {
    return this.#value.length;
  }

  /** Permite validar el prefijo público de una regla sin sacar el valor en claro. */
  hasPrefix(prefix: string): boolean {
    return this.#value.startsWith(prefix);
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
