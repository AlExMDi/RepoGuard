# Reference research — Gitleaks & TruffleHog

Notes on how two established scanners structure secret detection, used as a
reference for RepoGuard's own rule engine (not a dependency — RepoGuard
implements its own detection, but there's no reason to reinvent rule design
from scratch).

## Gitleaks

- Rules are defined in **TOML**, as a `[[rules]]` array. Each rule has:
  - `id` — unique identifier
  - `regex` — the Go regex used to match the secret
  - `secretGroup` — which capture group in the regex is the actual secret
  - `entropy` — a Shannon entropy threshold used to filter matches
  - `path` — optional regex on file path
  - `keywords` — cheap string pre-filters checked before running the regex,
    so the expensive regex only runs on lines that plausibly contain a hit
  - `tags`, `description` — metadata
- **Allowlisting** happens at two levels: per-rule (`[[rules.allowlists]]`)
  and global (`[[allowlists]]`), filtering by commit, path, or stopwords.
- **Composite/proximity rules**: a primary rule can require an auxiliary
  rule to also match within N lines/columns — useful for reducing false
  positives (e.g. a generic high-entropy string next to the word "password").
- Core design principle (their words): "regex is (almost) all you need" —
  entropy is a supplement, not the primary detector. Keywords exist purely
  as a speed optimization.

## TruffleHog

- Ships 800+ built-in detectors, one per credential type/provider (AWS,
  Stripe, Cloudflare, etc.) rather than a flat rule list.
- Detection pipeline has four phases: identification → classification →
  validation → analysis.
- Combines regex with entropy filtering (`--filter-entropy`, default
  threshold ~3.0) to drop low-entropy unverified matches.
- Distinctive feature: **live verification**. After a regex match, it
  actively calls the relevant provider API (e.g. AWS `GetCallerIdentity`)
  to confirm whether the credential is still valid. Results are tagged
  `verified` / `unverified` / `unknown`.
- Scans git history by default (not just the working tree). In CI it scopes
  scans with `--since-commit` / `--branch` to avoid re-scanning the whole
  repo on every push.

## What RepoGuard borrows for v1

| Concept | Source | RepoGuard v1 decision |
|---|---|---|
| Regex + entropy combo | Both | Adopt — regex first, entropy as secondary signal |
| Keyword pre-filter | Gitleaks | Adopt — cheap pre-check before regex on large repos |
| Rule metadata (id, tags, severity) | Gitleaks | Adopt, simplified — no proximity/composite rules in v1 |
| Full git history scan | TruffleHog | Adopt — scan history, not just working tree |
| Live credential verification | TruffleHog | Defer to v2 — adds network calls and provider-specific code the MVP doesn't need |
| Allowlisting | Gitleaks | Defer — v1 has no user-editable rule config yet |
