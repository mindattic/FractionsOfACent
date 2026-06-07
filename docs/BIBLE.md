---
codex: 1
project: FractionsOfACent
code: FOAC
layer: bible
status: living
updated: 2026-06-07
---

# FractionsOfACent — Project Bible

> Single source of truth for what FractionsOfACent IS, is NOT, and the rules that keep it coherent.
> README.md says how to build/run; this says how to think about the system.

## 1. The one sentence {#FOAC-§1}

FractionsOfACent is a public-service credential-leak pipeline: it watches public GitHub for exposed credentials, fingerprints each match (SHA-256) **without ever retaining the secret**, optionally files a courtesy issue on the leaker's own repo, and tracks whether the leak gets remediated — a CLI scanner and a Blazor Server review UI sharing one SQL Server LocalDB.

## 2. The product promise {#FOAC-§2}

- **Detection + disclosure + measurement — never exploitation.** The system records metadata only. It detects leaks, optionally discloses them to the leaker via a GitHub issue, and measures remediation over time.
- **Non-retention at the code level.** A raw regex match lives in one local variable, is hashed to SHA-256 + a short scheme prefix, and goes out of scope. It is never written to disk, logged, serialized, or returned from a function. See [`§5 LAW-1`](#FOAC-LAW-1).
- **Review precedes disclosure.** Every exposure type defaults to `auto_inform = false`. The auto-notify pass does nothing until a human flips a category on in the Web UI. See [`§5 LAW-2`](#FOAC-LAW-2).
- **The research artifact and the operator are the same binary.** Aggregate measurements (leak rate per provider, time-to-remediate, notice-to-remediation conversion) fall out of the pipeline for free.
- **One database, two front doors, race-safe.** The CLI scanner (`fractions`) and the Blazor UI read/write the same `FractionsOfACent` LocalDB via EF Core; multiple scanners can run while a human reviews. Pause/resume is coordinated through a single `ScannerControl` row. See [`§5 LAW-5`](#FOAC-LAW-5).
- **Loops forever, never crashes on a 403.** Default mode scans on a 60s cadence, paces itself against GitHub's 30 req/min Code Search limit, and absorbs rate-limit headers. See [`§5 LAW-3`](#FOAC-LAW-3).

## 3. What it is NOT {#FOAC-§3}

- **NOT a credential store.** It does not retrieve, retain, transmit, log, or return any raw credential — only the SHA-256 fingerprint, a 16-char scheme prefix, and the public repo/file pointers.
- **NOT a validator.** It never calls a provider API with a detected credential. Liveness is inferred from the recheck pass (does the hash still appear in the file?), never from authenticated probes.
- **NOT an offensive-security tool.** No exploitation, no pentest, no use of any found secret.
- **NOT a private-repo scanner.** Scope is public repositories indexed by GitHub Code Search only — no auth-walled endpoints, no cloning, no execution of repo code, no GitHub Enterprise.
- **NOT a rate-limit evader.** It does not rotate multiple PATs to multiply the budget (a GitHub AUP violation). For higher legitimate throughput, apply for GitHub Research Access.
- **NOT the retired v1.** The `v1/` Python scraper is retired reference only (see [`v1/DEPRECATED.md`](../v1/DEPRECATED.md)); do not extend it.

## 4. Architecture canon {#FOAC-§4}

```
                  ┌──────────────────────────────────────────────────┐
                  │                                                    │
   GitHub  ─►   1. Scan  ─►  2. Notify (gated)  ─►  3. Recheck  ───────┘
   Code Search                                       (every run)
   + Contents      └─ writes Findings           └─ writes
                                                   RemediationChecks
   leaker repo  ◄─── auto-issue (only when auto_inform=true)

   ┌─────────────┐        ┌──────────────────────────────┐        ┌──────────────┐
   │ Cli         │        │ Shared (library)             │        │ Blazor       │
   │ `fractions` │──uses──│ Db · Scraper-DTOs · Patterns │──uses──│ Server UI    │
   │ scan/notify │        │ NoticeService · GitHubClient │        │ Findings/Viz │
   │ /recheck    │        │ FractionsContext (EF Core)   │        │ /Settings    │
   └──────┬──────┘        └───────────────┬──────────────┘        └──────┬───────┘
          │                               │                              │
          └──────────────► SQL Server LocalDB `FractionsOfACent` ◄───────┘
                               (ScannerControl row coordinates pause/resume)
```

### 4.1 Projects
- **`FractionsOfACent.Shared`** ([`v2/Shared/`](../v2/Shared/)) — library: EF Core entities, DbContext, the `Db` persistence facade, detection patterns, notice service, GitHub client, settings. Consumed by both front doors.
- **`FractionsOfACent.Cli`** ([`v2/Cli/`](../v2/Cli/)) — the `fractions` executable: arg parsing, interactive + headless modes, the 3-phase pipeline, interactive TUI menu, heartbeat, HTML report.
- **`FractionsOfACent.Blazor`** ([`v2/Blazor/`](../v2/Blazor/)) — Blazor Server review UI: Findings table, Visualizations (KPIs + charts), Settings (pause/resume + per-type auto-inform).

### 4.2 Domain model (NOUNS)
EF entities are defined in [`v2/Shared/Entities.cs`](../v2/Shared/Entities.cs); mapping in [`v2/Shared/FractionsContext.cs`](../v2/Shared/FractionsContext.cs).
- **Finding** — one detected leak, keyed by `(KeySha256, RepoFullName, FilePath)`. Carries provider, exposure type, model hint, repo/file pointers, key prefix + length, first/last-seen. Never the secret.
- **ScannedFile** — a `(repo, path)` claim row; the atomic unit of concurrency-safe work distribution between scanners.
- **Notice** — a disclosure record keyed by `(KeySha256, RepoFullName, FilePath, Channel)`; the GitHub issue opened on the leaker repo, with status `sent`/`failed`.
- **RemediationCheck** — a time-stamped recheck result per finding (`present`/`removed`/`repo_gone`/`file_gone`/`fetch_failed`).
- **ExposureType** — the broad category lookup (`ApiKey`, `ConnectionString`, `PrivateKey`, `PlainTextPassword`), each with an `AutoInform` gate. Canon-as-data: see [`docs/data/exposure_types.json`](data/exposure_types.json).
- **ScannerControl** — single-row cross-process control surface: `RequestedState`, heartbeat, current label.
- **ProviderPattern** — one detection rule (provider, exposure type, regex, search needle, model hints) in [`v2/Shared/Patterns.cs`](../v2/Shared/Patterns.cs). Code-owned (regexes), keyed by `Provider`.

### 4.3 Key services (VERBS)
- **`Scraper.RunAsync`** ([`v2/Cli/Scraper.cs`](../v2/Cli/Scraper.cs)) — the 3-phase pipeline: scan (search → claim → fetch → `ScanContent` → upsert), `SendPendingNoticesAsync` (gated by auto-inform), `RecheckRemediationsAsync`. Writes the HTML report each pass.
- **`Db`** ([`v2/Shared/Db.cs`](../v2/Shared/Db.cs)) — persistence facade over `IDbContextFactory<FractionsContext>`; atomic `ClaimScan`/`ReleaseScan`, `UpsertFinding`, notice/recheck reads & writes, exposure-type auto-inform get/set, scanner control + heartbeat.
- **`NoticeService.SendAsync`** ([`v2/Shared/NoticeService.cs`](../v2/Shared/NoticeService.cs)) — idempotent issue-open + notice persistence; renders the courtesy template and calls `GitHubClient.OpenIssueAsync`.
- **`GitHubClient`** ([`v2/Shared/GitHubClient.cs`](../v2/Shared/GitHubClient.cs)) — `SearchCodeAsync`, `FetchFileAsync`, `RefetchAsync`, `OpenIssueAsync`; all rate-limit handling funnels through `HandleRateLimitAsync`.
- **`GitHubTokenProvider`** ([`v2/Shared/GitHubTokenProvider.cs`](../v2/Shared/GitHubTokenProvider.cs)) — resolves the PAT via `MindAttic.Vault` → User Secrets → `GITHUB_TOKEN` → legacy settings.json.

## 5. The Laws {#FOAC-§5}

> This project **inherits** the org-wide [MindAttic House Rules](../../MindAttic.HouseRules.md). Where a house law applies it is cited inline (`[see HOUSE-LAW-n]`) and NOT restated. The laws below are FractionsOfACent-specific.

### {#FOAC-LAW-1} FOAC-LAW-1 — Non-retention is enforced in code, not policy
The raw credential match exists in exactly one local variable, is reduced to `(SHA-256, 16-char prefix, length)` by `Scraper.Fingerprint`, and is dropped (`rawKey = null!`) before scope exit. It is never written to disk, logged, serialized, returned from a function, or persisted. This is the project's prime directive and an IRB-defensible property. (Extends org-wide secret hygiene — [see HOUSE-LAW-3](../../MindAttic.HouseRules.md#HOUSE-LAW-3).)

### {#FOAC-LAW-2} FOAC-LAW-2 — Disclosure is opt-in per exposure type; review precedes action
Every `ExposureType.AutoInform` defaults to `false`. The auto-notify pass (`Scraper.SendPendingNoticesAsync`) files an issue ONLY for types a human has flipped on in the Web UI. Filing a public issue against an innocent repo is reputational harm, so review-then-act is the safe default. This is a project-specific specialization of [HOUSE-LAW-2 (soft-disable / reversible by default)](../../MindAttic.HouseRules.md#HOUSE-LAW-2).

### {#FOAC-LAW-3} FOAC-LAW-3 — The scanner never crashes on a rate limit
All GitHub rate-limit handling funnels through `GitHubClient.HandleRateLimitAsync` (honors `Retry-After`, `X-RateLimit-Remaining=0`/`Reset`, falls back to a 60s secondary back-off). The `--loop` mode rides this out indefinitely; an unexpected pass failure is logged and the loop continues. Indefinite, self-pacing operation is the contract.

### {#FOAC-LAW-4} FOAC-LAW-4 — No credential validation, ever
The tool never calls a provider API with a detected credential. Remediation liveness is inferred solely by re-fetching the public file and re-hashing (`RecheckRemediationsAsync`), never by an authenticated probe. Do not rotate multiple PATs to evade rate limits (GitHub AUP).

### {#FOAC-LAW-5} FOAC-LAW-5 — One engine, many front doors, one race-safe database
The CLI and Blazor app register the identical `Shared` engine and read/write the same SQL Server LocalDB. Concurrent scanners coordinate through atomic `ClaimScan` (PK-uniqueness) and the single `ScannerControl` row; pause/resume works from either surface. (Project realization of [HOUSE-LAW-6](../../MindAttic.HouseRules.md#HOUSE-LAW-6).)

### {#FOAC-LAW-6} FOAC-LAW-6 — Credentials resolve through MindAttic.Vault
The GitHub PAT is resolved by `GitHubTokenProvider` via the `MindAttic.Vault` configuration source (then User Secrets, then `GITHUB_TOKEN`, then a deprecated legacy file). No token is committed; the repo `.gitignore` defends against a stray `settings.json`. (Direct application of [HOUSE-LAW-3](../../MindAttic.HouseRules.md#HOUSE-LAW-3).)

## 6. Verified state {#FOAC-§6}

Build/test evidence recorded 2026-06-07 (dotnet 10.0.300, Windows PowerShell 5.1):

- **Build: GREEN.** `dotnet build FractionsOfACent.sln -c Release` → **Build succeeded, 0 Warning(s), 0 Error(s)** (all three projects: `Shared`, `Cli`, `Blazor`). This is the strongest current evidence.
- **Tests: NONE.** No automated test project exists in the repo (no `*.Tests` project; `git ls-files` finds no test sources). Every story in [USER_STORIES.md](USER_STORIES.md) is therefore `🟡` at best on the "verified by test" axis — see the audit note there. Closing this is the #1 frontier item ([§7](#FOAC-§7), [RFC 0001](rfc/0001-verification-harness.md)).
- **Runtime evidence:** the `--headless` one-shot CLI mode is runnable and CI-shaped (exits non-zero on a failed pass); `findings.db*` and `findings.htm` from prior runs are present but git-ignored (current persistence is SQL Server LocalDB).

> `tools/codex.ps1 doctor` checks that every file path cited in this bible exists on disk; it passed clean (0 errors, 0 warnings) on 2026-06-07.

## 7. Active frontier {#FOAC-§7}

- **Testing gap (highest priority):** there is no automated test suite. The non-retention guarantee ([LAW-1](#FOAC-LAW-1)), the auto-inform gate ([LAW-2](#FOAC-LAW-2)), and concurrency safety ([LAW-5](#FOAC-LAW-5)) are all asserted by code structure but not proven by tests. See [RFC 0001](rfc/0001-verification-harness.md) and the priority backlog in [USER_STORIES.md](USER_STORIES.md).
- **Open epics:** see Epics in [USER_STORIES.md](USER_STORIES.md) — Detection, Disclosure, Remediation tracking, Review UI, Operations.

## 8. Quality bar {#FOAC-§8}

A feature is **done** (`✅`) only when:
1. `dotnet build FractionsOfACent.sln -c Release` is clean (no new warnings in changed files).
2. A test or a reproducible run proves the behavior — and the story in [USER_STORIES.md](USER_STORIES.md) names that evidence. (Org-wide: [HOUSE-LAW-8](../../MindAttic.HouseRules.md#HOUSE-LAW-8).)
3. The non-retention invariant ([LAW-1](#FOAC-LAW-1)) is preserved — no new code path persists, logs, or returns a raw match.
4. Anything touching disclosure respects the auto-inform gate ([LAW-2](#FOAC-LAW-2)).
5. Versioning, when bumped, follows whole-number rules ([HOUSE-LAW-1](../../MindAttic.HouseRules.md#HOUSE-LAW-1)).

## 9. Glossary {#FOAC-§9}

- **Exposure type** — broad category of a leak: `ApiKey`, `ConnectionString`, `PrivateKey`, `PlainTextPassword`. Carries the `auto_inform` gate. Canon: [`docs/data/exposure_types.json`](data/exposure_types.json).
- **Provider** — the specific source of a credential (`anthropic`, `aws-access-key`, `postgres-uri`, …); maps to one `ProviderPattern`.
- **Finding** — a detected leak, identified by SHA-256 fingerprint + repo + file path. Never contains the secret.
- **Fingerprint** — `(SHA-256 hex, 16-char scheme prefix, length)` computed from a raw match; the only thing persisted.
- **Notice** — a courtesy GitHub issue opened on the leaker's repo disclosing the finding.
- **Remediation check** — a re-fetch + re-hash that determines whether a previously-found leak is still present.
- **auto_inform** — per-exposure-type boolean gate; when `false` (default) the CLI never auto-files an issue for that type.
- **ScannerControl** — the single DB row that lets the Web UI pause/resume any running scanner.
- **Heartbeat** — periodic `LastHeartbeatUtc` + `CurrentLabel` write so the UI can show scanner liveness.
- **Headless / one-shot** — `--headless` with no `--loop`: a single CI-friendly pass that exits non-zero on failure.
- **MindAttic.Vault** — shared configuration source resolving secrets from `%APPDATA%\MindAttic\...`.
