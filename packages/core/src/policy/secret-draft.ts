import type { Severity } from "../domain/finding";
import type { RawSecretMatch } from "../domain/raw-secret-match";
import type { Hasher } from "../ports/crypto";
import { fingerprint } from "./fingerprint";
import { redact } from "./redact";

/** Una aparición de un secreto, ya sin el valor en claro. */
export interface SecretOccurrence {
  fingerprint: string;
  ruleId: string;
  severity: Severity;
  title: string;
  redacted: string;
  length: number;
  location: RawSecretMatch["location"];
  inWorkingTree: boolean;
  ordinal: number;
}

/** Calcula fingerprint y redacción y descarta el SecretValue (spec finding-runscan §2.1). */
export function secretDraft(match: RawSecretMatch, salt: string, hash: Hasher): SecretOccurrence {
  const { ruleId, severity, title, location, inWorkingTree, ordinal, value } = match;
  return {
    fingerprint: fingerprint({ salt, ruleId, value }, hash),
    ruleId,
    severity,
    title,
    ...redact(match),
    location,
    inWorkingTree,
    ordinal,
  };
}
