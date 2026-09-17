# Dashboard wireframes (v1)

Three screens cover the MVP: repo list, finding detail, and report export.
Sketched here as ASCII layout; worth redoing in
[Excalidraw](https://excalidraw.com/) once the component structure firms up,
but this is enough to start building the React views against.

## 1. Repo list (landing page after login)

```
┌─────────────────────────────────────────────────────────────┐
│ RepoGuard              [search repos...]      (user) ▾ logout│
├─────────────────────────────────────────────────────────────┤
│  Repos                                                        │
│                                                                 │
│  ┌───────────────────────────────────────────────────────┐   │
│  │ ● my-api-service              🔴 3 critical  12 total   │   │
│  │   last scan: 2h ago · commit a1b2c3d                    │   │
│  ├───────────────────────────────────────────────────────┤   │
│  │ ● portfolio-site              🟡 0 crit · 2 med          │   │
│  │   last scan: 1d ago · commit 9f8e7d6                    │   │
│  ├───────────────────────────────────────────────────────┤   │
│  │ ● internal-tools              🟢 clean                  │   │
│  │   last scan: 3d ago · commit 5c4b3a2                    │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                                 │
│  Repos appear here automatically the first time you run        │
│  `repoguard scan` against them.                                │
└─────────────────────────────────────────────────────────────┘
```

- Severity dot/badge is the highest severity across the repo's latest scan.
- Clicking a row goes to the finding detail view for that repo's latest scan.

## 2. Finding detail

```
┌─────────────────────────────────────────────────────────────┐
│ ← my-api-service          commit a1b2c3d · 2h ago  [Export ▾]│
├─────────────────────────────────────────────────────────────┤
│  [ All (12) ] [ Secrets (3) ] [ Dependencies (7) ] [ Misconfig (2) ]│
│                                                                 │
│  🔴 CRITICAL · secret                                          │
│  AWS Access Key exposed                                        │
│  config/deploy.sh:14                                           │
│  ─────────────────────────────────────────────────────────    │
│  🟠 HIGH · dependency                                           │
│  lodash 4.17.15 — CVE-2021-23337 (prototype pollution)         │
│  package.json                                                  │
│  ─────────────────────────────────────────────────────────    │
│  🟡 MEDIUM · misconfig                                          │
│  .env committed to repository                                  │
│  .env:1                                                        │
│                                                                 │
│  [ Evolution over time chart — findings count per scan ]       │
└─────────────────────────────────────────────────────────────┘
```

- Filter tabs by category match the `findings.category` enum in the data
  model ([04-data-model.md](04-data-model.md)).
- The evolution chart plots `scans.findings_count` over `scans.finished_at`
  for this repo.

## 3. Export report

```
┌─────────────────────────────────────────────────────┐
│  Export report — my-api-service                      │
│                                                        │
│  Format:   ( ) Markdown    ( ) PDF                    │
│  Scope:    ( ) This scan only  ( ) Full history        │
│                                                        │
│                          [ Cancel ]  [ Download ]      │
└─────────────────────────────────────────────────────┘
```

- Backed by the `GET /reports/:id` endpoint from
  [03-architecture-flow.md](03-architecture-flow.md).

## Auth screens

Standard login/register forms — email + password, link between the two,
no wireframe needed beyond that; not a differentiator worth designing
before the rest of the app exists.
