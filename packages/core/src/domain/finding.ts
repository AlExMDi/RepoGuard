// Listas en runtime, no solo tipos: core valida lo que envían los escáneres (spec §2.2).
export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export const CATEGORIES = ["secret", "dependency", "misconfig"] as const;

export type Severity = (typeof SEVERITIES)[number];
export type Category = (typeof CATEGORIES)[number];

/** Umbral de --fail-on: "none" no hace fallar nunca por hallazgos. */
export type FailOn = Severity | "none";

export type FindingLocation =
  | { kind: "file"; path: string; line?: number; column?: number; commit?: string }
  | { kind: "package"; lockfile: string; ecosystem: string; name: string; version: string };

export interface Finding {
  /** fingerprint (secret) o hash estable sin número de línea (spec finding-runscan §2.3). */
  id: string;
  category: Category;
  ruleId: string;
  severity: Severity;
  title: string;
  location: FindingLocation;
  /** Solo material ya redactado: nunca un SecretValue. */
  secret?: { redacted: string; length: number; inWorkingTree: boolean; occurrences: number };
  vuln?: { osvId: string; aliases: string[]; fixedIn?: string; url: string };
  suppressed: boolean;
}
