#requires -Version 5.1
<#
    SessionStart hook: inject docs/BIBLE.digest.md into Claude Code's context as
    authoritative project canon. Emits Claude Code hook JSON on stdout.

    Win-1252 / PowerShell 5.1 safe: all non-ASCII is escaped to \uXXXX so the
    JSON is valid regardless of console code page. If the digest is missing or
    empty, emits {} (no-op).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Write-Empty { Write-Output '{}'; exit 0 }

try {
    $hookDir  = $PSScriptRoot
    $repoRoot = Split-Path -Parent (Split-Path -Parent $hookDir)
    $digest   = Join-Path $repoRoot 'docs/BIBLE.digest.md'

    if (-not (Test-Path $digest)) { Write-Empty }
    $body = [System.IO.File]::ReadAllText($digest)
    if ([string]::IsNullOrWhiteSpace($body)) { Write-Empty }

    $preamble = @"
[FractionsOfACent — Codex canon, injected at session start]
The following is the AUTHORITATIVE project digest, generated from docs/BIBLE.md.
Treat it as the source of truth for what the project IS, is NOT, and its Laws.
Full detail lives in docs/BIBLE.md; amendments in docs/AMENDMENTS.md win over the
bible. Reference facts by their {#FOAC-...} IDs. Do not retain raw credentials
(FOAC-LAW-1); disclosure is opt-in per exposure type (FOAC-LAW-2).

"@

    $context = $preamble + $body

    # Build JSON manually so we control escaping (5.1 ConvertTo-Json mangles
    # some unicode + is verbose). Escape per JSON string rules, then \uXXXX
    # everything outside printable ASCII.
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $context.ToCharArray()) {
        $code = [int][char]$ch
        switch ($ch) {
            '"'  { [void]$sb.Append('\"') }
            '\'  { [void]$sb.Append('\\') }
            "`b" { [void]$sb.Append('\b') }
            "`f" { [void]$sb.Append('\f') }
            "`n" { [void]$sb.Append('\n') }
            "`r" { [void]$sb.Append('\r') }
            "`t" { [void]$sb.Append('\t') }
            default {
                if ($code -lt 32 -or $code -gt 126) {
                    [void]$sb.Append('\u' + $code.ToString('x4'))
                } else {
                    [void]$sb.Append($ch)
                }
            }
        }
    }
    $escaped = $sb.ToString()

    $json = '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"' + $escaped + '"}}'
    Write-Output $json
    exit 0
}
catch {
    # Never break a session on a hook error.
    Write-Output '{}'
    exit 0
}
