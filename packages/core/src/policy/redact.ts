import { SecretValue } from "../domain/secret-value";

export interface RedactInput {
  publicPrefix: string | null;
  kindLabel: string;
  value: SecretValue;
}

/**
 * `ghp_****` o `[private key, RSA]`, más la longitud aparte (mvp §7).
 * No lee el valor: el prefijo sale de la regla y la longitud del campo privado.
 */
export function redact({ publicPrefix, kindLabel, value }: RedactInput): {
  redacted: string;
  length: number;
} {
  const redacted = publicPrefix === null ? `[${kindLabel}]` : `${publicPrefix}****`;
  return { redacted, length: SecretValue.lengthOf(value) };
}
