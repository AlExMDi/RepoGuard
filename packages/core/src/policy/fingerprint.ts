import type { SecretValue } from "../domain/secret-value";
import type { Hasher } from "../ports/crypto";

const SALT_HEX = /^[0-9a-f]{64}$/;
const utf8 = new TextEncoder();

/** Sal en hex minúscula, o null si no son 32 bytes en hex (acepta mayúsculas). */
export function normalizeSalt(salt: string): string | null {
  const lower = salt.toLowerCase();
  return SALT_HEX.test(lower) ? lower : null;
}

export interface FingerprintInput {
  /** 32 bytes en hex (del baseline o aleatoria por ejecución). */
  salt: string;
  ruleId: string;
  value: SecretValue;
}

/** hex(SHA-256(salt ‖ 0x00 ‖ ruleId ‖ 0x00 ‖ secreto)) — mvp §7. */
export function fingerprint({ salt, ruleId, value }: FingerprintInput, hash: Hasher): string {
  // El mensaje nunca incluye la sal ni el secreto.
  if (!SALT_HEX.test(salt)) throw new Error("fingerprint: salt must be 32 bytes of lowercase hex");

  const saltBytes = Uint8Array.from(salt.match(/../g) ?? [], (h) => parseInt(h, 16));
  const rule = utf8.encode(ruleId);
  const secret = utf8.encode(value.unsafeReveal());

  const bytes = new Uint8Array(saltBytes.length + 1 + rule.length + 1 + secret.length);
  let offset = 0;
  for (const part of [saltBytes, [0], rule, [0], secret]) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return hash(bytes);
}
