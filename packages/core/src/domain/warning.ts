export const WARNING_CODES = [
  "SCANNER_FAILED",
  "SCANNER_CONTRACT_VIOLATION",
  "FILE_TOO_LARGE",
  "BINARY_SKIPPED",
  "LINE_TRUNCATED",
  "UNPINNED_DEPENDENCIES",
  "LOCKFILE_INVALID",
  "REQUIREMENTS_ESCAPE",
  "OSV_UNAVAILABLE",
  "SHALLOW_CLONE",
  "CACHE_RESET",
  "BASELINE_INVALID",
  "BASELINE_UPDATE_REFUSED",
  "BASELINE_SAVE_FAILED",
] as const;

export const WARNING_REASONS = ["partial-scan", "invalid-baseline"] as const;

export type WarningCode = (typeof WARNING_CODES)[number];
export type WarningReason = (typeof WARNING_REASONS)[number];

/**
 * Sin campos de texto libre: el texto lo genera el reporter, que sanea `path`.
 * Así un aviso no puede contener el contenido de una línea (spec finding-runscan §2.6).
 */
export interface Warning {
  code: WarningCode;
  path?: string;
  count?: number;
  reason?: WarningReason;
}
