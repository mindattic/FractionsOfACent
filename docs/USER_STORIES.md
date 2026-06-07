---
codex: 1
project: FractionsOfACent
code: FOAC
layer: stories
status: living
updated: 2026-06-07
---

# FractionsOfACent — User Stories

> ✅ done (shipped & tested) · 🟡 partial (shipped, not test-proven) · ⬜ planned · 🗑️ cut.
> Every ✅ cites the test that proves it. **This repo currently has no automated test project**
> (`git ls-files` finds no `*.Tests` sources), so no story can be ✅ on the "verified by test"
> axis yet — shipped behavior is marked 🟡 with the strongest available evidence. Closing the
> testing gap is the top priority ([RFC 0001](rfc/0001-verification-harness.md), [FOAC-§7](BIBLE.md#FOAC-§7)).

## Epic A — Detection

- **FOAC-US-A1 🟡** As an operator, I can scan public GitHub for leaked credentials across many providers (LLM, cloud, VCS, payments, comms, DB URIs, private keys), so I find real exposures. *Given a GitHub PAT, When I run `fractions --headless`, Then it searches each provider needle, fetches matches, and records `Finding` rows.* *(Shipped: `Scraper.RunAsync` + `Patterns.All` in [`v2/Cli/Scraper.cs`](../v2/Cli/Scraper.cs), [`v2/Shared/Patterns.cs`](../v2/Shared/Patterns.cs). No verifying test — see audit note.)*
- **FOAC-US-A2 🟡** As a researcher, the scanner records metadata only and never retains the raw secret, so the project is IRB-defensible ([FOAC-LAW-1](BIBLE.md#FOAC-LAW-1)). *Given a match, When it is recorded, Then only SHA-256 + 16-char prefix + length persist.* *(Shipped: `Scraper.Fingerprint`, `rawKey = null!` after hashing. NO automated test asserts non-retention — this invariant is the #1 thing to test.)*
- **FOAC-US-A3 🟡** As an operator, I can opt into high-false-positive PlainTextPassword patterns separately, so they never pollute the default scan. *Given `--include-passwords`, When I scan, Then `Patterns.WithPasswords()` is used; otherwise it is not.* *(Shipped: `Patterns.WithPasswords`, gated by the `--include-passwords` flag in [`v2/Cli/Program.cs`](../v2/Cli/Program.cs).)*

## Epic B — Disclosure

- **FOAC-US-B1 🟡** As an operator, the scanner never auto-files an issue until I flip a category on, so innocent repos aren't harmed ([FOAC-LAW-2](BIBLE.md#FOAC-LAW-2)). *Given all exposure types default `auto_inform=false`, When the notify pass runs, Then it sends nothing.* *(Shipped: `Scraper.SendPendingNoticesAsync` auto-inform gate; seed defaults `AutoInform=false` in [`v2/Shared/Db.cs`](../v2/Shared/Db.cs).)*
- **FOAC-US-B2 🟡** As an operator, I can file a courtesy issue on a leaker's repo with the fingerprint (never the secret), so they can rotate. *Given a finding, When I send a notice, Then a GitHub issue is opened and a `Notice` row recorded idempotently.* *(Shipped: `NoticeService.SendAsync` → `GitHubClient.OpenIssueAsync`.)*
- **FOAC-US-B3 🟡** As an operator, sending a notice twice for the same finding+channel is a no-op, so I never spam a repo. *Given an existing `sent` notice, When I send again, Then it returns `Skipped=true` without re-opening.* *(Shipped: idempotency check in `NoticeService.SendAsync`.)*

## Epic C — Remediation tracking

- **FOAC-US-C1 🟡** As a researcher, each run re-checks existing findings to see if the leak was removed, so I can measure time-to-remediate. *Given prior findings, When the recheck pass runs, Then it re-fetches + re-hashes and writes a `RemediationCheck` (`present`/`removed`/`repo_gone`/`file_gone`).* *(Shipped: `Scraper.RecheckRemediationsAsync`.)*
- **FOAC-US-C2 🟡** As an operator, remediation rechecks are capped per run, so a large DB doesn't burn the whole API budget. *Given `--max-rechecks N`, When the pass runs, Then at most N findings are re-checked, stalest first.* *(Shipped: `_maxRechecks` ordering by `CheckedAtUtc`.)*

## Epic D — Review UI (Blazor)

- **FOAC-US-D1 🟡** As a reviewer, I see a live, paginated table of every finding with notice + remediation status, so I can triage. *(Shipped: [`v2/Blazor/Components/Pages/Findings.razor`](../v2/Blazor/Components/Pages/Findings.razor), 3s live polling.)*
- **FOAC-US-D2 🟡** As a researcher, I see KPIs and charts (cumulative findings/notices/remediations, time-to-remediate, by-provider, status donut), so I can report aggregates. *(Shipped: [`v2/Blazor/Components/Pages/Visualizations.razor`](../v2/Blazor/Components/Pages/Visualizations.razor) + [`v2/Blazor/VizData.cs`](../v2/Blazor/VizData.cs).)*
- **FOAC-US-D3 🟡** As an operator, I can pause/resume the scanner and toggle per-type auto-inform from the UI, so I control disclosure without restarting the CLI. *(Shipped: [`v2/Blazor/Components/Pages/Settings.razor`](../v2/Blazor/Components/Pages/Settings.razor) writing `ScannerControl` + `SetAutoInform`.)*

## Epic E — Operations

- **FOAC-US-E1 🟡** As an operator, the scanner loops forever and never crashes on a 403, so it can run unattended ([FOAC-LAW-3](BIBLE.md#FOAC-LAW-3)). *(Shipped: `RunLoopAsync` + `GitHubClient.HandleRateLimitAsync`.)*
- **FOAC-US-E2 🟡** As a CI user, `--headless` with no `--loop` runs a single pass and exits non-zero on failure, so it is automatable. *(Shipped: one-shot branch in [`v2/Cli/Program.cs`](../v2/Cli/Program.cs).)*
- **FOAC-US-E3 🟡** As an operator, multiple scanners can run concurrently against one DB without double-scanning a file ([FOAC-LAW-5](BIBLE.md#FOAC-LAW-5)). *(Shipped: atomic `Db.ClaimScan`/`ReleaseScan` via PK uniqueness. Concurrency is asserted by structure, not by a test.)*

## Priority backlog

Dependency-ordered toward a test-proven, IRB-defensible pipeline:

1. ⬜ **Stand up a test project** (`FractionsOfACent.Tests`) — unblocks every ✅. ([RFC 0001](rfc/0001-verification-harness.md))
2. ⬜ **Non-retention test** proving `Scraper.Fingerprint`/`ScanContent` emit only fingerprints (FOAC-US-A2 → ✅).
3. ⬜ **Pattern-matching tests** with synthetic-key fixtures per provider (FOAC-US-A1 → ✅).
4. ⬜ **Auto-inform gate test** proving the notify pass is a no-op when all types are off (FOAC-US-B1 → ✅).
5. ⬜ **Notice idempotency test** (FOAC-US-B3 → ✅).
6. ⬜ **Remediation status-transition test** over a fake `GitHubClient` (FOAC-US-C1 → ✅).
7. ⬜ **Concurrency test** for `ClaimScan` race (FOAC-US-E3 → ✅).

### Audit log

- **No story was rewritten from a prior spec.** This is the first Codex story set for FractionsOfACent; it was derived from `README.md`, the source tree, and the (now superseded) ad-hoc docs. There is no pre-existing `user_stories.md` to preserve.
- **Status honesty note (original spec — audit log):** the README presents many capabilities as shipped facts. Because the repo has **no automated tests**, this Codex deliberately downgrades all shipped behavior to `🟡` rather than `✅`, per [HOUSE-LAW-8](../../MindAttic.HouseRules.md#HOUSE-LAW-8) and [FOAC-§8](BIBLE.md#FOAC-§8). Behavior is real and runnable; it is simply not test-proven.
