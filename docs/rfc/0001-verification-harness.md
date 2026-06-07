---
codex: 1
project: FractionsOfACent
code: FOAC
layer: rfc
status: planned
updated: 2026-06-07
---

# RFC 0001 — A verification harness for the non-retention and disclosure invariants

## Problem

FractionsOfACent's most important properties — **non-retention of secrets** ([FOAC-LAW-1](../BIBLE.md#FOAC-LAW-1)), **review-before-disclosure** ([FOAC-LAW-2](../BIBLE.md#FOAC-LAW-2)), and **race-safe concurrency** ([FOAC-LAW-5](../BIBLE.md#FOAC-LAW-5)) — are currently guaranteed only by code structure and reviewer discipline. There is **no automated test project** in the repo. That means no `✅` story exists, and a refactor could silently regress the IRB-defensible guarantees the project rests on.

## Options compared

1. **No tests, rely on review.** Status quo. Cheap, but the prime directive is unprotected and "done" can never be honestly claimed.
2. **Full end-to-end tests hitting GitHub.** Highest fidelity, but slow, rate-limited, non-deterministic, and would require a live PAT in CI — at odds with the project's own ethics.
3. **Unit/integration tests against a faked `GitHubClient` + in-memory or LocalDB EF context.** Deterministic, fast, no network, isolates each invariant. Requires making `GitHubClient` substitutable (interface or virtual seam) — a source change, so out of scope for the docs migration but the recommended next step.

## Decision

Pursue **Option 3**. Add a `FractionsOfACent.Tests` project that fakes the GitHub boundary and exercises the `Shared` engine + `Scraper` directly. Prioritize, in order: non-retention, pattern matching, auto-inform gate, notice idempotency, remediation transitions, concurrency claim.

## What NOT to do

- Do **not** put a real credential (even an expired one) in a fixture. Use synthetic strings shaped to match the regexes.
- Do **not** call any provider API or open real GitHub issues from tests.
- Do **not** weaken `Scraper.Fingerprint`'s drop-after-hash structure to make it more testable; test the observable output (only fingerprints are emitted), not internals that would invite retention.

## Phased plan (with risk)

1. **Seam (low risk):** extract an interface for the GitHub boundary so tests can inject a fake. *Risk: touches `Shared` source — separate PR, separate review.*
2. **Harness (low risk):** stand up `FractionsOfACent.Tests`, wire LocalDB/in-memory EF.
3. **Invariant tests (medium):** non-retention + auto-inform gate first; these protect the laws.
4. **Coverage (medium):** patterns, idempotency, remediation, concurrency.

## Graduates into

- [BIBLE §6 — Verified state](../BIBLE.md#FOAC-§6) (flip evidence from "build only" to test-cited).
- [USER_STORIES.md](../USER_STORIES.md) — promotes FOAC-US-A1/A2, B1/B3, C1, E3 from 🟡 to ✅ as each test lands.
