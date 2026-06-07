---
codex: 1
project: FractionsOfACent
code: FOAC
layer: amendments
status: living
updated: 2026-06-07
---

# FractionsOfACent — Amendments (append-only; amendment wins over the bible)

> Append-only change log. Never rewrite an amendment; supersede it with a new one. Beyond ~25,
> fold into [BIBLE.md](BIBLE.md) and start a new epoch (note the git tag). History stays in git.

## FOAC-A1 — Adopt the Codex documentation standard (supersedes —)

**What changed.** Installed the MindAttic Codex canonical-documentation layout: [`docs/BIBLE.md`](BIBLE.md) (L0), this amendments log (L1), [`docs/USER_STORIES.md`](USER_STORIES.md) (L2), [`docs/rfc/`](rfc/) design notes, [`docs/data/`](data/) canon-as-data (L5), a generated [`docs/BIBLE.digest.md`](BIBLE.digest.md), the [`tools/codex.ps1`](../tools/codex.ps1) doctor/digest CLI, and the `.claude/hooks/inject-digest.ps1` SessionStart hook.

**Why.** Prior to this, the only canon was prose in `README.md` plus the retired-v1 pointer in `v1/DEPRECATED.md` — facts (architecture, laws, status) were not addressable by stable ID and "done" was asserted, not verified.

**Migration.**
- `README.md` is unchanged and remains the build/run reference; [BIBLE.md](BIBLE.md) now owns "how to think about the system."
- The org-wide laws are inherited by reference from [`MindAttic.HouseRules.md`](../../MindAttic.HouseRules.md); only FractionsOfACent-specific laws live in [BIBLE §5](BIBLE.md#FOAC-§5).
- The `ExposureTypes` catalog (previously duplicated between `README.md` and [`v2/Shared/Patterns.cs`](../v2/Shared/Patterns.cs)) is now canon-as-data at [`docs/data/exposure_types.json`](data/exposure_types.json) with a schema; prose cites entities by `id`.
- Status was set honestly: with no automated test project present, all shipped stories are `🟡`, not `✅` ([HOUSE-LAW-8](../../MindAttic.HouseRules.md#HOUSE-LAW-8)).

**Documentation correction (not a code change).** The `README.md` non-retention section cites `v2/Cli/Scraper.cs` method `ScanItemAsync`; the actual method is `ScanContent` (called from `RunAsync`). [BIBLE §4.3](BIBLE.md#FOAC-§4) cites the real symbol. The README wording is left untouched per the no-source-edit constraint of this migration; a future RFC may correct it.
