# v1 — Python implementation, retired

The Python scraper has been **retired**. As of 2026-04-25,
FractionsOfACent is a C#-only application: the scanner, the notice
pipeline, the recheck pass, the Blazor UI, and the SQLite owner all
live under `v2/`. This `v1/` directory is the historical Python side,
kept on disk for reference only.

## Why this directory still exists

These files mirror an earlier era when the project ran two parallel
scrapers (C# + Python) against the same SQLite DB. The Python side
never grew the broader exposure-type coverage (AWS, GitHub, payments,
DB URIs, private keys, contextual passwords) that the C# side now
has, and the notify/recheck/Blazor pipeline was C#-only from the
start.

## Do not run

The code in this directory is not maintained. Do not run it against
the production `findings.db`:

- `db.py` here predates the `exposure_types` table seeding logic and
  has no migrations for any future schema additions.
- `scraper.py` produces `Finding` rows without an `exposure_type`
  field; while the SQLite default keeps that column populated, the
  Python scraper will drift further from the C# scanner's coverage
  every release.
- `disclosure.py` and `report.py` are superseded by the Blazor UI's
  Findings + Visualizations tabs.

If you need a Python-side touch (e.g. an ad-hoc analytical query for
the thesis), open the SQLite DB read-only and write a one-off script
outside this directory.

## What replaced what

| Old (v1, Python) | New (v2, C#) |
|---|---|
| `v1/scraper.py` | `v2/Cli/Scraper.cs` + `v2/Cli/Program.cs` |
| `v1/patterns.py` | `v2/Shared/Patterns.cs` |
| `v1/db.py` | `v2/Shared/Db.cs` |
| `v1/disclosure.py` | `v2/Shared/NoticeService.cs` + Blazor UI's Findings tab |
| `v1/report.py` | `v2/Cli/Report.cs` + Blazor UI's Visualizations tab |
| `v1/requirements.txt` | n/a — `v2/Cli/FractionsOfACent.Cli.csproj` |
