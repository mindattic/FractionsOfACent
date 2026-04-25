# FractionsOfACent

A public-service credential-disclosure pipeline for public GitHub
repositories. It detects leaked credentials, opens a courtesy issue on
the leaker's repo asking them to rotate, and tracks whether the leak
gets remediated. Originated as a Masters-thesis dataset (LLM API key
prevalence) and now covers a broader credential surface — see
**Exposure types** below.

The system records **metadata only** — the credentials themselves are
never persisted, logged, or returned from any function. The defensible
hash-and-discard property is preserved across the new patterns and the
new auto-notify path.

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
to the SQLite DB at `--out`. With `--loop`, the binary becomes a daemon
that paces itself against GitHub rate limits and re-runs forever.

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
`exposure_types` SQLite lookup table, joined to `findings.exposure_type`:

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
  trail (notices table + remediation_checks table) so you can report
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
│   │   ├── Db.cs               # SQLite schema, migrations, queries
│   │   ├── Finding.cs
│   │   ├── Notice.cs           # Notice + RemediationCheck records
│   │   ├── NoticeService.cs    # Issue-opening + notice persistence
│   │   ├── GitHubClient.cs     # Search, fetch, refetch, open-issue
│   │   ├── Patterns.cs         # ProviderPattern[] + ExposureTypes
│   │   └── Settings.cs
│   ├── Cli/                    # FractionsOfACent.Cli (exe)
│   │   ├── Program.cs          # arg parsing, --loop daemon mode
│   │   ├── Scraper.cs          # 3-phase pipeline (scan/notify/recheck)
│   │   └── Report.cs
│   └── Blazor/                 # FractionsOfACent.Blazor (Blazor Server)
│       ├── Program.cs          # DI + render pipeline
│       ├── VizData.cs          # Visualizations data plumbing
│       ├── Components/
│       │   ├── Pages/
│       │   │   ├── Findings.razor          # Tab 1: paginated table
│       │   │   └── Visualizations.razor    # Tab 2: charts + KPIs
│       │   ├── CumulativeChart.razor
│       │   ├── HistogramChart.razor
│       │   ├── ProviderBarChart.razor
│       │   └── DonutChart.razor
│       ├── wwwroot/app.css
│       └── appsettings.json
└── v1/          # retired — see v1/DEPRECATED.md
```

The C# Cli and the Web app both read/write the same SQLite file. WAL
+ busy_timeout makes concurrent access from multiple Cli instances
(e.g. one foreground + a `--loop` daemon) race-safe.

## Running

### Scanner CLI

```bash
cd v2/Cli
dotnet build
export GITHUB_TOKEN=ghp_xxx           # or settings.json (see below)

# Single pass (default behaviour):
dotnet run -- --out ../../findings.db --max-per-provider 50

# Daemon mode — never quits, paces itself against rate limits:
dotnet run -- --out ../../findings.db --loop 30m

# Include the opt-in PlainTextPassword patterns (high FP rate):
dotnet run -- --out ../../findings.db --include-passwords --loop 1h
```

Useful flags:

- `--loop INTERVAL` — run the full pipeline forever, sleeping `INTERVAL`
  between passes. Accepts `60`, `30s`, `5m`, `1h`, `1d`. Rate limits
  are absorbed internally (Retry-After → primary reset → secondary
  60s back-off); the loop never crashes on a 403.
- `--max-rechecks N` (default 100) / `--no-recheck` — caps the per-run
  remediation-recheck work.
- `--max-notices N` (default 25) / `--no-notify` — caps the per-run
  auto-notify volume. Only fires for types with `auto_inform=true`.
- `--include-passwords` — opt into the contextual + shape-based
  PlainTextPassword patterns.
- `--provider X` — narrow to one or more providers (repeatable).

### Web UI

```bash
cd v2/Blazor
dotnet run --urls http://localhost:5000
```

Two tabs:

- **Findings** — paginated table of every finding, with columns for
  exposure type, provider, repo, file, first-seen date, notice
  status, remediation status, and check-back count. Per-row `Send`
  button manually files an issue. Collapsible auto-inform panel lets
  you flip categories on/off. Live-updates every 3s while the page is
  open (a small "live" indicator pulses near the page title).
- **Visualizations** — KPI strip (Exposed LLM Credentials, Filed
  Issues, Remediated, % Remediated, Avg Time-to-Remediate, Avg
  Check-Backs Until Remediated) plus charts: cumulative findings vs.
  notices vs. remediations, time-to-remediate distribution,
  check-backs-until-remediated histogram, by-provider breakdown,
  remediation-status donut. Same live polling.

The Web app reads `appsettings.json` for `FractionsOfACent:DbPath`
(default `../../findings.db` so it points at the repo root). Override
the notice template by setting `NoticeChannel` / `NoticeTitle` /
`NoticeBody` keys; otherwise the in-code default in
[`NoticeService.cs`](v2/Shared/NoticeService.cs) is used.

## GitHub PAT

Both the CLI and the Web app read the token from (in order):

1. `GITHUB_TOKEN` env var
2. `%APPDATA%\MindAttic\FractionsOfACent\settings.json` (Windows) or
   `~/.config/MindAttic/FractionsOfACent/settings.json`:

   ```json
   { "github_token": "github_pat_..." }
   ```

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
