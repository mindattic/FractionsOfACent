---
name: scan
description: Start the FractionsOfACent CLI scanner in headless looped mode. Continuously scans for exposed credentials until the user stops it.
---

When invoked:

1. From the project root (`D:\Projects\MindAttic\FractionsOfACent`), launch the CLI in the background with a log file:

   ```
   dotnet run --project v2/Cli -- --headless --loop 60
   ```

   Use the Bash tool with `run_in_background: true` and redirect output to `scan-run.log` (e.g. `dotnet run --project v2/Cli -- --headless --loop 60 > scan-run.log 2>&1`).

2. Report back:
   - The background shell id (so the user can monitor/stop it).
   - The log path (`scan-run.log`) and the `fractions` invocation used.
   - A reminder that the scanner pauses/resumes via the `ScannerControl` row (Blazor Settings tab) or by killing the background shell.

Flags the user may ask for — pass them after the `--` in the dotnet command:
- `--loop 30s|5m|1h` — change cadence (default here is 60s).
- `--provider <name>` (repeatable) — restrict to specific providers.
- `--include-passwords` — opt into PlainTextPassword patterns (high FP rate).
- `--max-per-provider N`, `--max-rechecks N`, `--max-notices N` — tune per-pass caps.
- `-v` / `--verbose` — extra config logging.

Notes:
- Headless mode obeys `ScannerControl.RequestedState`, so the Blazor UI's pause button works without restarting.
- Auto-notify defaults to off for every exposure type; the loop scans + rechecks but won't open issues until a category is flipped on in the Web UI.
- Persistence is SQL Server LocalDB (`FractionsOfACent` database) — the Blazor app can run concurrently against the same DB.
- To stop: kill the background shell (or use the user's pause control). Do not auto-stop on the user's behalf.
