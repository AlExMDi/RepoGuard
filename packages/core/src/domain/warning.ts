export type WarningCode =
  | "SCANNER_FAILED"
  | "SCANNER_CONTRACT_VIOLATION"
  | "FILE_TOO_LARGE"
  | "BINARY_SKIPPED"
  | "LINE_TRUNCATED"
  | "UNPINNED_DEPENDENCIES"
  | "LOCKFILE_INVALID"
  | "REQUIREMENTS_ESCAPE"
  | "OSV_UNAVAILABLE"
  | "SHALLOW_CLONE"
  | "CACHE_RESET"
  | "BASELINE_INVALID"
  | "BASELINE_UPDATE_REFUSED";

export type WarningReason = "partial-scan" | "invalid-baseline";

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
