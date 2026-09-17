# End-to-end flow

CLI scans a repo → posts the structured result to the API → dashboard reads
it from the API and renders it. The CLI never talks to the dashboard
directly, and the dashboard never scans anything itself — the API is the
only contract between the two.

```mermaid
flowchart LR
    subgraph Local["Developer machine / CI runner"]
        REPO[(Local repo\nworking tree + git history)]
        CLI["repoguard CLI\nrepoguard scan ./repo"]
    end

    subgraph Engine["Scan engine (inside CLI)"]
        SECRETS["Secret detector\nregex + entropy"]
        DEPS["Dependency checker\npackage.json / requirements.txt\n-> OSV.dev API"]
        MISCONFIG["Misconfig checks\n.env committed, risky\nActions permissions"]
    end

    subgraph Backend["Backend API"]
        AUTH["Auth\npersonal API token"]
        INGEST["POST /scans\nreceive + persist result"]
        QUERY["GET /repos, /scans, /findings\nGET /reports/:id"]
    end

    DB[(PostgreSQL\nrepos, scans, findings)]

    subgraph Frontend["Dashboard (React)"]
        LIST["Repo list\nseverity summary"]
        DETAIL["Finding detail\nby category, file, line"]
        EXPORT["Export report\nPDF / Markdown"]
    end

    OSV[["OSV.dev API"]]

    REPO --> CLI
    CLI --> SECRETS & DEPS & MISCONFIG
    DEPS -.query.-> OSV
    SECRETS --> RESULT["Structured JSON\nfindings[]"]
    DEPS --> RESULT
    MISCONFIG --> RESULT
    RESULT -- "POST + API token" --> AUTH
    AUTH --> INGEST
    INGEST --> DB
    QUERY --> DB
    LIST --> QUERY
    DETAIL --> QUERY
    EXPORT --> QUERY
```

## Key decisions this diagram locks in

- **The CLI does all scanning locally.** Source code never leaves the
  developer's machine except as the already-redacted/structured findings
  JSON (file + line + finding metadata — not raw file contents). This is
  what "local-first" means for RepoGuard in practice.
- **The API is dumb on purpose.** It persists what the CLI sends and serves
  it back; it does not re-scan or re-interpret findings.
- **OSV.dev is called from the CLI, not the backend** — dependency data is
  part of the scan, resolved before the result is ever sent over the wire.
- **Auth is a personal API token for the CLI**, separate from the
  session-based login used by the dashboard (see task 6, "Autenticación y
  autorización reales").
