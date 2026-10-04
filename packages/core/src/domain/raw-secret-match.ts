import type { Severity } from "./finding";
import type { SecretValue } from "./secret-value";

/** Lo que emite un escáner de secretos. runScan lo convierte en Finding y descarta `value`. */
export interface RawSecretMatch {
  ruleId: string;
  severity: Severity;
  title: string;
  /** Prefijo público de la regla (`ghp_`); null en reglas sin prefijo (PEM). */
  publicPrefix: string | null;
  /** Tipo legible para reglas sin prefijo, p. ej. "private key, RSA". */
  kindLabel: string;
  value: SecretValue;
  location: { path: string; line: number; column: number; commit?: string };
  inWorkingTree: boolean;
  /** Orden de aparición: historial del más antiguo al más reciente, árbol de trabajo al final. */
  ordinal: number;
}
