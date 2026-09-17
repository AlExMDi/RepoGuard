# MVP Scope — RepoGuard v1

RepoGuard is a local-first security scanner for repositories: CLI + dashboard,
meant to run against your own repos or in CI — not a SaaS that requires
granting a third party access to your source code.

## What v1 detects

### 1. Exposed secrets
- Regex-based detection for known secret formats (API keys, tokens, private
  keys, common credential patterns) — see [02-research-gitleaks-trufflehog.md](02-research-gitleaks-trufflehog.md)
  for how Gitleaks/TruffleHog structure their rule sets.
- Shannon entropy scoring as a secondary signal, to catch high-entropy
  strings that don't match a known pattern (generic tokens, random secrets).
- Scans both the current working tree and full commit history, since a
  secret removed in a later commit is still exposed in git history.

### 2. Vulnerable dependencies
- Parses manifest files (`package.json`, `requirements.txt` for v1) and
  queries the [OSV.dev](https://osv.dev/docs/) API for known vulnerabilities.
- Reports affected package, installed version, vulnerability ID, and
  severity as provided by OSV.

### 3. Basic misconfigurations
- `.env` (or other secret-bearing files) committed to the repo.
- Overly permissive GitHub Actions workflow permissions.

## What v1 explicitly does NOT do (deferred)

- No custom rule authoring UI (rules are built-in, not user-editable).
- No verification of live secrets against provider APIs (unlike TruffleHog's
  verified/unverified/unknown model) — that's a credible v2 addition once the
  detection core is solid.
- No multi-language dependency manifests beyond npm/pip (no Maven, Cargo,
  Go modules, etc., in v1).
- No SAST / custom code-vulnerability analysis (that's a different problem
  from secrets + dependencies + misconfig).
- No team/org features — auth exists so each user sees only their own data,
  not for role-based access control across a team.

## Output shape

Every scan produces a structured result: a list of **findings**, each with
a category (`secret` | `dependency` | `misconfig`), severity, file + line
(or package + version), and a short description. This structured JSON is
the contract between the CLI and the backend API — see
[03-architecture-flow.md](03-architecture-flow.md).

## Definition of done for the MVP

- `repoguard scan ./some-repo` runs locally, no network calls required
  except the OSV.dev lookup, and prints findings to the terminal as JSON
  or a human-readable table.
- The same JSON result can be POSTed to the backend and shows up correctly
  in the dashboard, grouped by category with severity.
- A user can log in, see their scanned repos, drill into a repo's findings,
  and export a report.
