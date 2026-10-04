export interface RepoInfo {
  root: string;
  headCommit?: string;
  shallow: boolean;
}

/** REPO_ERROR: describe() lanzó una excepción (su mensaje no se conserva). */
export type RepoFatalCode = "NOT_A_GIT_REPO" | "GIT_MISSING" | "REPO_ERROR";

export type RepoDescription =
  { kind: "ok"; info: RepoInfo } | { kind: "fatal"; code: RepoFatalCode };

/**
 * Parte de RepoReader que necesita runScan. Los métodos de lectura de ficheros y blobs
 * se añaden con los escáneres, que reciben su RepoReader por constructor desde cli.
 */
export interface RepoReader {
  describe(): Promise<RepoDescription>;
}
