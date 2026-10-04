export type Severity = "critical" | "high" | "medium" | "low";
export type Category = "secret" | "dependency" | "misconfig";

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
