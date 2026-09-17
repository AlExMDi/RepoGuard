# Data model

Four core entities: users, repos, scans, findings. A scan belongs to a repo
and a repo belongs to a user; a scan produces many findings.

```mermaid
erDiagram
    USERS ||--o{ REPOS : owns
    REPOS ||--o{ SCANS : "has history of"
    SCANS ||--o{ FINDINGS : produces

    USERS {
        uuid id PK
        string email UK
        string password_hash
        string api_token UK "personal token used by the CLI"
        timestamp created_at
    }

    REPOS {
        uuid id PK
        uuid user_id FK
        string name
        string local_path_hint "informational only, never enforced server-side"
        timestamp created_at
    }

    SCANS {
        uuid id PK
        uuid repo_id FK
        string commit_sha
        string status "completed | failed"
        int findings_count
        string highest_severity "critical | high | medium | low"
        timestamp started_at
        timestamp finished_at
    }

    FINDINGS {
        uuid id PK
        uuid scan_id FK
        string category "secret | dependency | misconfig"
        string severity "critical | high | medium | low"
        string rule_id "e.g. aws-access-key, osv-CVE-2023-xxxx"
        string file_path
        int line_number "nullable — deps/misconfig may not have a line"
        string package_name "nullable — only for category=dependency"
        string package_version "nullable"
        text description
        timestamp created_at
    }
```

## Notes

- **`repos` has no notion of a git remote URL as a required field** — a repo
  scanned locally may never be pushed anywhere. `local_path_hint` is purely
  informational (shown in the dashboard for context), never used for access
  control or re-fetching.
- **`scans.commit_sha`** ties a scan to the exact commit that was scanned,
  which is what makes the "evolution of findings over time" chart (task 7)
  possible — plot `findings_count` per scan, ordered by `finished_at`.
- **`findings.rule_id`** is intentionally a free-form string rather than a
  foreign key to a `rules` table — v1 has no user-editable rule config
  (see [02-research-gitleaks-trufflehog.md](02-research-gitleaks-trufflehog.md)),
  so rules live in the CLI's code, not the database.
- Access control (task 6) is enforced at the query layer: every `SCANS` /
  `FINDINGS` lookup joins through `REPOS.user_id = current_user.id` — there
  is no separate ACL table for v1, ownership is the only access rule.
