export interface BaselineEntry {
  fingerprint: string;
  ruleId: string;
  note: string;
}

/** `.repoguard-baseline.json` (mvp §2.5). `salt` son 32 bytes en hex. */
export interface Baseline {
  version: 1;
  salt: string;
  entries: BaselineEntry[];
}
