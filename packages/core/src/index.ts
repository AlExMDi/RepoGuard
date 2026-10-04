// API pública de @repoguard/core. Las políticas (policy/) y los dobles (testing/) son
// internos: solo los usa runScan y sus tests.

// Dominio
export type { Baseline, BaselineEntry } from "./domain/baseline";
export type { Category, FailOn, Finding, FindingLocation, Severity } from "./domain/finding";
export type { RawSecretMatch } from "./domain/raw-secret-match";
export type { CategoryReport, CategoryStatus, ScanResult } from "./domain/scan-result";
export { SecretValue } from "./domain/secret-value";
export type { Warning, WarningCode, WarningReason } from "./domain/warning";

// Puertos
export type { BaselineLoad, BaselineStore } from "./ports/baseline-store";
export type { Clock } from "./ports/clock";
export type { Hasher, RandomBytes } from "./ports/crypto";
export type { RepoDescription, RepoFatalCode, RepoInfo, RepoReader } from "./ports/repo-reader";
export type { FindingDraft, ScanContext, Scanner, ScannerEvent } from "./ports/scanner";

// Caso de uso
export {
  runScan,
  type RunScanDeps,
  type RunScanOptions,
  type RunScanOutcome,
} from "./use-cases/run-scan";
