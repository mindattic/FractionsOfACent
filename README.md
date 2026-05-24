# FractionsOfACent

**Public-service credential-leak detection. Find leaks, file courtesy issues, measure remediation — never store the secret.**

A pipeline that watches public GitHub for exposed credentials — API keys, connection strings, private keys, plaintext passwords — opens a courtesy issue on the leaker's own repo asking them to rotate, then tracks whether the leak actually gets fixed. Originated as a Masters-thesis dataset on LLM API key prevalence; now covers the broader credential surface (see [Exposure types](#exposure-types)).

The system records **metadata only**. Raw matches are SHA-256 hashed and discarded inside one function. No credential is persisted, logged, transmitted, returned from a function, or validated against any provider API. Detection, disclosure, and measurement — not exploitation.

**Why FractionsOfACent:**

- **Hash-and-discard at the code level.** The raw match exists in one local variable, gets hashed, and the variable goes out of scope. There is no path to disk for the credential itself — only the fingerprint, scheme prefix, and repo URL.
- **Auto-inform is opt-in per category.** Every exposure type defaults to `auto_inform = false`. The CLI never files an issue until a human flips a category on in the Web UI. False positives against innocent repos are reputational damage; review precedes disclosure.
- **The research artifact and the operator are the same binary.** Aggregate measurements (leak rate per provider, time-to-remediate, notice-to-remediation conversion) fall out for free as the pipeline runs.
- **Loops forever by default.** Run with no args and the CLI scans on a 60s cadence, paces itself against GitHub's 30 req/min Code Search limit, absorbs `Retry-After` headers, and never crashes on a 403. `--headless` drops the menu for sidecar use; `--loop 5m` changes the cadence.
- **One SQL Server LocalDB, two front ends.** The CLI scanner and the Blazor Server review UI both read/write the same `FractionsOfACent` database via EF Core — multiple scanners can run concurrently while a human is reviewing in the browser. Pause/resume from either surface is coordinated through a single `ScannerControl` row.
- **IRB-defensible audit trail.** Every notice filed (and every remediation check that follows) is recorded in the same database, so you can report exactly what was sent, when, to whom, and what happened next.

---

## Table of Contents

- [Pipeline at a glance](#pipeline-at-a-glance)
- [Why this exists](#why-this-exists)
- [Exposure types](#exposure-types)
- [Research ethics & non-retention](#research-ethics--non-retention)
- [Methodology precedent](#methodology-precedent)
- [Repository layout](#repository-layout)
- [Running](#running)
  - [Scanner CLI](#scanner-cli)
  - [Web UI](#web-ui)
- [GitHub PAT](#github-pat)
- [Rate limits](#rate-limits)
- [What this tool does NOT do](#what-this-tool-does-not-do)

---

## Pipeline at a glance

```
                ┌──────────────────────────────────────────────────┐
                │                                                  │
   GitHub  ─►   1. Scan  ─►  2. Notify (gated)  ─►  3. Recheck  ───┘
   Code Search                                       (every run)
   + Contents      └─ writes findings           └─ writes
                                                   remediation_checks
   leaker repo  ◄─── auto-issue (only when auto_inform=true)
```

Each invocation runs all three phases in order and persists everything
to the SQL Server LocalDB `FractionsOfACent` database (override with
`--connection` or the `FRACTIONS_DB` env var). The default mode loops
forever every 60s with an interactive menu; `--headless` drops the
menu and pairs with `--loop` for daemon/sidecar use.

## Why this exists

Leaked LLM keys, cloud credentials, payment-provider tokens, and DB
connection strings are an active abuse vector on public GitHub.
Providers run secret-scanning partner programs, and GitHub's Push
Protection blocks many of them at push time. **What's missing is the
public-service tier**: a third-party that observes the leaks, files a
courteous notice on the leaker's own repo, then watches whether the
leak gets remediated. That's what this project does.

The research artifact and the public-service operator are the same
binary. Aggregate measurements (leak rate per provider, time-to-
remediate, notice-to-remediation conversion) fall out for free as the
pipeline runs.

## Exposure types

Findings are categorized into four broad types via the
`ExposureTypes` lookup table, joined to `Findings.ExposureType`:

| Type | What it covers | Auto-inform default |
|---|---|---|
| `ApiKey` | Provider tokens — Anthropic, OpenAI (incl. legacy), Google Gemini, AWS access keys, GitHub PATs (classic + fine + OAuth + app variants), Stripe live secret/restricted, Slack bot/user/webhook, Discord webhooks, Twilio, SendGrid, Mailgun, npm, PyPI, DigitalOcean PAT/OAuth, Shopify (private + access), Square access/secret, JWT | `false` |
| `ConnectionString` | Postgres / MySQL / MongoDB / Redis URIs containing inline `user:pass@host` | `false` |
| `PrivateKey` | PEM-encoded private key blocks: RSA, OpenSSH, EC, PGP | `false` |
| `PlainTextPassword` | Contextual `password = "..."` literals + opt-in shape patterns. Opt-in only via `--include-passwords` because of the false-positive rate | `false` |

**Every type defaults to `auto_inform = false`** — the CLI's auto-notify
pass does nothing until you flip a category on in the Web UI. This is
deliberate: false positives that auto-file public issues against
innocent repos = real reputational harm. You review, then approve.

The Web UI can either flip a whole category to auto-inform, or send
notices manually per finding, or do both.

## Research ethics & non-retention

- **Scope**: public repositories indexed by GitHub Code Search. No
  private data, no auth-walled endpoints, no cloning, no execution of
  repo code.
- **Non-retention** is enforced at the code level. The raw regex match
  is bound to a local variable, used to compute SHA-256 + a short scheme
  prefix, then dropped. It is never written to disk, emitted to logs,
  serialized, or returned from a function. See
  [`v2/Cli/Scraper.cs`](v2/Cli/Scraper.cs) `ScanItemAsync`.
- **No validation**: the tool does not call provider APIs with detected
  credentials. Liveness is inferred from the recheck pass (does the
  hash still appear in the file?), not authenticated probes.
- **Public disclosure via issues**: the `Notify` pass opens a GitHub
  issue on the leaker's own repo. The issue body is markdown, links to
  the offending file, and includes only the SHA-256 fingerprint and
  scheme prefix — never the secret itself. The repo owner is `@`-mentioned
  so GitHub's notification system emails them automatically.
- **IRB note**: opening a public issue on someone's repo is a
  third-party disclosure act. For a thesis-committee record, document
  this as part of your IRB submission. The project keeps the audit
  trail (`Notices` table + `RemediationChecks` table) so you can report
  exactly what was sent, when, to whom, and what happened next.

## Methodology precedent

Hash-and-discard methodology follows:

> Meli, M., McNiece, M. R., & Reaves, B. (2019).
> *How Bad Can It Git? Characterizing Secret Leakage in Public GitHub
> Repositories.* NDSS.
> <https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/>

## Repository layout

```
FractionsOfACent/
├── v2/
│   ├── Shared/                 # FractionsOfACent.Shared (library)
│   │   ├── Entities.cs         # EF Core entity types
│   │   ├── FractionsContext.cs # DbContext + model config
│   │   ├── Db.cs               # Query/command facade used by both apps
│   │   ├── Finding.cs
│   │   ├── Notice.cs           # Notice + RemediationCheck records
│   │   ├── NoticeService.cs    # Issue-opening + notice persistence
│   │   ├── GitHubClient.cs     # Search, fetch, refetch, open-issue
│   │   ├── GitHubTokenProvider.cs  # MindAttic.Vault + env + legacy resolver
│   │   ├── Patterns.cs         # ProviderPattern[] + ExposureTypes
│   │   └── Settings.cs         # LocalDB default + config paths
│   ├── Cli/                    # FractionsOfACent.Cli (exe — `fractions`)
│   │   ├── Program.cs          # arg parsing, interactive + headless modes
│   │   ├── Scraper.cs          # 3-phase pipeline (scan/notify/recheck)
│   │   ├── Menu.cs             # interactive TUI: p/r/s/q keys
│   │   ├── Heartbeat.cs        # writes ScannerControl heartbeat each pass
│   │   └── Report.cs           # renders findings.htm
│   └── Blazor/                 # FractionsOfACent.Blazor (Blazor Server)
│       ├── Program.cs          # DI + render pipeline
│       ├── VizData.cs          # Visualizations data plumbing
│       ├── Components/
│       │   ├── Pages/
│       │   │   ├── Findings.razor          # Tab 1: paginated table
│       │   │   ├── Visualizations.razor    # Tab 2: charts + KPIs
│       │   │   └── Settings.razor          # Tab 3: pause/resume + auto-inform
│       │   ├── CumulativeChart.razor
│       │   ├── HistogramChart.razor
│       │   ├── ProviderBarChart.razor
│       │   └── DonutChart.razor
│       ├── wwwroot/app.css
│       └── appsettings.json
└── v1/          # retired Python reference; do not extend
```

The CLI and the Web app both read/write the same SQL Server LocalDB
`FractionsOfACent` database. EF Core + SQL Server's MVCC make concurrent
access from multiple CLI instances (e.g. an interactive session + a
`--headless --loop` sidecar) race-safe. Pause/resume coordinates through
the single `ScannerControl` row.

## Running

### Scanner CLI

```powershell
dotnet build v2/Cli
$env:GITHUB_TOKEN = "github_pat_..."   # or User Secrets / vault (see below)

# Interactive (default) — scans every 60s in the background; in-terminal
# menu accepts [p]ause, [r]esume, [s]tatus, [q]uit. Pause/resume route
# through the same ScannerControl row the Blazor Settings tab uses.
dotnet run --project v2/Cli

# Headless sidecar — no menu, loops indefinitely, obeys ScannerControl:
dotnet run --project v2/Cli -- --headless --loop 5m

# Headless one-shot — single pass and exit (CI-friendly):
dotnet run --project v2/Cli -- --headless

# Override the database (defaults to SQL Server LocalDB):
dotnet run --project v2/Cli -- --connection "Server=...;Database=..."

# Opt into PlainTextPassword patterns (high FP rate):
dotnet run --project v2/Cli -- --include-passwords --loop 1h
```

Or via the project's `/scan` skill, which launches `--headless --loop 60`
in the background and tails to `scan-run.log`.

Useful flags:

- `--headless` — no interactive menu. Loops indefinitely with `--loop`,
  otherwise runs a single pass and exits. Pair with `--loop` for sidecar
  use; obeys `ScannerControl.RequestedState` so the Blazor UI can still
  pause it.
- `--loop INTERVAL` — sleeps `INTERVAL` between passes. Accepts `60`,
  `30s`, `5m`, `1h`, `1d`. Rate limits are absorbed internally
  (Retry-After → primary reset → secondary 60s back-off); the loop never
  crashes on a 403. Default cadence is 60s when omitted in a long-lived
  mode (interactive or `--headless` without one-shot).
- `--connection "<conn-string>"` — override the SQL Server connection.
  Also accepts the `FRACTIONS_DB` env var.
- `--report PATH` — output `.htm` report path (default `findings.htm`,
  regenerated each pass from the full DB).
- `--max-rechecks N` (default 100) / `--no-recheck` — caps the per-run
  remediation-recheck work.
- `--max-notices N` (default 25) / `--no-notify` — caps the per-run
  auto-notify volume. Only fires for types with `auto_inform=true`.
- `--include-passwords` — opt into the contextual + shape-based
  PlainTextPassword patterns.
- `--provider X` — narrow to one or more providers (repeatable).
- `-v` / `--verbose` — extra config logging.

### Web UI

```powershell
dotnet run --project v2/Blazor
```

Default URLs are `https://localhost:50676` / `http://localhost:50677`
(see `v2/Blazor/Properties/launchSettings.json`).

Three tabs:

- **Findings** — paginated table of every finding, with columns for
  exposure type, provider, repo, file, first-seen date, notice
  status, remediation status, and check-back count. Per-row `Send`
  button manually files an issue. Live-updates every 3s while the page
  is open (a small "live" indicator pulses near the page title).
- **Visualizations** — KPI strip (Exposed LLM Credentials, Filed
  Issues, Remediated, % Remediated, Avg Time-to-Remediate, Avg
  Check-Backs Until Remediated) plus charts: cumulative findings vs.
  notices vs. remediations, time-to-remediate distribution,
  check-backs-until-remediated histogram, by-provider breakdown,
  remediation-status donut. Same live polling.
- **Settings** — scanner pause/resume (writes to the same
  `ScannerControl` row the CLI menu uses) plus auto-inform toggles
  per exposure type. Heartbeat age from the scanner side is shown so
  you can confirm the sidecar is alive.

The Web app reads `appsettings.json` for `ConnectionStrings:Fractions`
(defaults to SQL Server LocalDB `FractionsOfACent`). Override the
notice template by setting `FractionsOfACent:NoticeChannel` /
`NoticeTitle` / `NoticeBody`; otherwise the in-code default in
[`NoticeService.cs`](v2/Shared/NoticeService.cs) is used.

## GitHub PAT

Token resolution is centralized in `GitHubTokenProvider` (uses the
shared `MindAttic.Vault` configuration source). The CLI and the Web
app try sources in this order:

1. `MindAttic.Vault` — `%APPDATA%\MindAttic\GitHub\tokens.json`
   (`{ "github": "github_pat_..." }`)
2. .NET User Secrets — `dotnet user-secrets set "MindAttic:Vault:Tokens:github" "github_pat_..."`
   from `v2/Cli` or `v2/Blazor` (both projects share the
   `mindattic-vault-shared` secrets id)
3. `GITHUB_TOKEN` env var
4. Legacy `%APPDATA%\MindAttic\FractionsOfACent\settings.json`
   `{ "github_token": "github_pat_..." }` (deprecated — migrate to one
   of the above)

A fine-grained PAT with public-repo read **and `Issues: write`** is
sufficient for the full pipeline. (Issues:write is needed because the
Notify pass opens issues; if you only ever scan, public-repo read is
enough.)

## Rate limits

GitHub authenticated rate limits:

- Primary REST: 5,000 req/hour per token
- Code Search: 30 req/min per token (the binding constraint)
- Issue creation: subject to a stricter content-creation secondary limit

The pipeline's `HandleRateLimitAsync` respects `Retry-After`,
`X-RateLimit-Remaining=0`/`X-RateLimit-Reset`, and falls back to a 60s
back-off for secondary limits without an explicit hint. The `--loop`
mode is designed to ride this out indefinitely. **Do not rotate
multiple PATs to multiply the budget — that violates GitHub's
Acceptable Use Policy.** For higher legitimate throughput, apply for
GitHub Research Access (academic study).

## What this tool does NOT do

- It does not retrieve, retain, or transmit any credential.
- It does not validate credentials against provider APIs.
- It does not scrape private repos, commits behind auth, or GitHub
  Enterprise.
- It does not rotate or cycle PATs to evade rate limits.
- It is not a pentest or offensive-security tool. It is detection +
  disclosure + measurement.
