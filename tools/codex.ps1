#requires -Version 5.1
<#
.SYNOPSIS
    Codex documentation CLI for FractionsOfACent — doctor + digest.

.DESCRIPTION
    doctor : validates the docs/ canon (front-matter, stable IDs, cross-refs,
             JSON-schema, story test tokens, cited file paths, digest freshness)
             and exits non-zero on any hard error.
    digest : regenerates docs/BIBLE.digest.md from BIBLE.md sections 1, 3, 5, 9
             plus a status index and the latest amendment head.

    Pure PowerShell, no build step. Windows PowerShell 5.1 safe (no pwsh-only syntax).

.EXAMPLE
    powershell -NoProfile -File tools/codex.ps1 doctor
    powershell -NoProfile -File tools/codex.ps1 digest
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('doctor', 'digest')]
    [string]$Command = 'doctor'
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

# --- Paths -----------------------------------------------------------------
$RepoRoot = Split-Path -Parent $PSScriptRoot
$DocsDir  = Join-Path $RepoRoot 'docs'
$BiblePath   = Join-Path $DocsDir 'BIBLE.md'
$StoriesPath = Join-Path $DocsDir 'USER_STORIES.md'
$AmendPath   = Join-Path $DocsDir 'AMENDMENTS.md'
$DigestPath  = Join-Path $DocsDir 'BIBLE.digest.md'
$RfcDir      = Join-Path $DocsDir 'rfc'
$DataDir     = Join-Path $DocsDir 'data'
$SchemaDir   = Join-Path $DataDir '_schema'

$script:Errors   = New-Object System.Collections.Generic.List[string]
$script:Warnings = New-Object System.Collections.Generic.List[string]
$script:Checks   = New-Object System.Collections.Generic.List[string]

function Add-Error([string]$m)   { $script:Errors.Add($m) }
function Add-Warning([string]$m) { $script:Warnings.Add($m) }
function Add-Check([string]$m)   { $script:Checks.Add($m) }

function Read-AllText([string]$path) {
    return [System.IO.File]::ReadAllText($path)
}

# --- YAML front-matter parser (key: value only; sufficient for codex blocks) ---
function Get-FrontMatter([string]$path) {
    $text = Read-AllText $path
    $text = $text -replace "^\xEF\xBB\xBF", ''   # strip BOM if present
    if ($text -notmatch '^\s*---\r?\n') { return $null }
    $lines = $text -split "\r?\n"
    if ($lines[0].Trim() -ne '---') { return $null }
    $map = @{}
    for ($i = 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i].Trim() -eq '---') { return $map }
        if ($lines[$i] -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$') {
            $map[$matches[1]] = $matches[2].Trim()
        }
    }
    return $null  # no closing fence
}

$ValidLayers = @('bible', 'stories', 'amendments', 'rfc', 'data', 'houserules')

function Test-FrontMatter([string]$path, [string]$expectedLayer) {
    $rel = $path.Substring($RepoRoot.Length).TrimStart('\', '/')
    $fm = Get-FrontMatter $path
    if ($null -eq $fm) {
        Add-Error "front-matter: $rel has no valid 'codex:' YAML front-matter block"
        return
    }
    foreach ($req in @('codex', 'project', 'code', 'layer', 'updated')) {
        if (-not $fm.ContainsKey($req)) {
            Add-Error "front-matter: $rel missing required key '$req'"
        }
    }
    if ($fm.ContainsKey('codex') -and $fm['codex'] -ne '1') {
        Add-Error "front-matter: $rel has codex='$($fm['codex'])' (expected 1)"
    }
    if ($fm.ContainsKey('layer')) {
        if ($expectedLayer -and $fm['layer'] -ne $expectedLayer) {
            Add-Error "front-matter: $rel layer='$($fm['layer'])' (expected '$expectedLayer')"
        }
        if ($ValidLayers -notcontains $fm['layer']) {
            Add-Error "front-matter: $rel has unknown layer '$($fm['layer'])'"
        }
    }
    if ($fm.ContainsKey('updated') -and $fm['updated'] -notmatch '^\d{4}-\d{2}-\d{2}$') {
        Add-Error "front-matter: $rel 'updated' is not YYYY-MM-DD ('$($fm['updated'])')"
    }
}

# Same checks for JSON data files (codex metadata embedded as JSON keys).
function Test-JsonFrontMatter($obj, [string]$rel) {
    foreach ($req in @('codex', 'project', 'code', 'layer', 'updated')) {
        if (-not ($obj.PSObject.Properties.Name -contains $req)) {
            Add-Error "front-matter: $rel (JSON) missing required key '$req'"
        }
    }
    if (($obj.PSObject.Properties.Name -contains 'codex') -and ($obj.codex -ne 1)) {
        Add-Error "front-matter: $rel (JSON) codex=$($obj.codex) (expected 1)"
    }
    if (($obj.PSObject.Properties.Name -contains 'layer') -and ($obj.layer -ne 'data')) {
        Add-Error "front-matter: $rel (JSON) layer='$($obj.layer)' (expected 'data')"
    }
    if (($obj.PSObject.Properties.Name -contains 'updated') -and ($obj.updated -notmatch '^\d{4}-\d{2}-\d{2}$')) {
        Add-Error "front-matter: $rel (JSON) 'updated' is not YYYY-MM-DD"
    }
}

function Get-MarkdownFiles {
    $files = @($BiblePath, $StoriesPath, $AmendPath)
    if (Test-Path $RfcDir) {
        $files += (Get-ChildItem -Path $RfcDir -Filter '*.md' -File | ForEach-Object { $_.FullName })
    }
    return $files
}

# --- Anchor / cross-ref check ---------------------------------------------
function Test-AnchorsAndRefs {
    $files = Get-MarkdownFiles
    $allAnchors = @{}          # anchor -> file (uniqueness across corpus)
    $dupAnchors = @{}
    $refs = New-Object System.Collections.Generic.List[object]

    foreach ($f in $files) {
        if (-not (Test-Path $f)) { continue }
        $rel = $f.Substring($RepoRoot.Length).TrimStart('\', '/')
        $text = Read-AllText $f

        # Declared anchors: {#ANCHOR}. The section anchors contain the section
        # sign; reference it by code point to keep this script ASCII-clean.
        $SECT = [char]0x00A7
        $declMatches = [regex]::Matches($text, ('\{#([A-Za-z0-9_.' + $SECT + '-]+)\}'))
        foreach ($m in $declMatches) {
            $a = $m.Groups[1].Value
            if ($allAnchors.ContainsKey($a)) {
                $dupAnchors[$a] = $true
            } else {
                $allAnchors[$a] = $rel
            }
        }

        # Cross-references: markdown links ending in #ANCHOR
        $linkMatches = [regex]::Matches($text, '\]\(([^)]*#[^)]+)\)')
        foreach ($m in $linkMatches) {
            $target = $m.Groups[1].Value
            $refs.Add([pscustomobject]@{ File = $rel; Target = $target; Source = $f })
        }
    }

    foreach ($a in $dupAnchors.Keys) {
        Add-Error "anchors: duplicate {#$a} declared more than once"
    }

    # Resolve each cross-ref's #fragment against known anchors (same corpus only).
    foreach ($r in $refs) {
        $hashIdx = $r.Target.IndexOf('#')
        if ($hashIdx -lt 0) { continue }
        $pathPart = $r.Target.Substring(0, $hashIdx)
        $frag = $r.Target.Substring($hashIdx + 1)

        # Skip links that point outside the codex corpus (e.g. HouseRules,
        # README, external docs.github.com) — anchor existence there is not
        # this tool's responsibility, but the file path is checked elsewhere.
        $isHouseRules = $pathPart -match 'HouseRules\.md$'
        $isExternal   = $pathPart -match '^https?://'
        if ($isHouseRules -or $isExternal) { continue }

        # In-corpus fragment must resolve to a declared anchor.
        if ($allAnchors.ContainsKey($frag)) { continue }

        # GitHub-style auto-anchors (lower-case heading slugs) are allowed for
        # intra-doc section links; only flag FOAC-style IDs that should exist.
        if ($frag -match '^(FOAC|HOUSE)-') {
            Add-Error "cross-ref: $($r.File) links to #$frag which is not a declared anchor"
        }
    }

    Add-Check "anchors: $($allAnchors.Count) unique IDs declared; $($refs.Count) cross-ref link(s) scanned"
}

# --- Cited file paths exist -----------------------------------------------
function Test-CitedPaths {
    $missing = 0
    $checked = 0
    foreach ($f in (Get-MarkdownFiles)) {
        if (-not (Test-Path $f)) { continue }
        $rel = $f.Substring($RepoRoot.Length).TrimStart('\', '/')
        $dir = Split-Path -Parent $f
        $text = Read-AllText $f
        # Markdown links whose target is a relative path (no scheme, no pure #anchor).
        $linkMatches = [regex]::Matches($text, '\]\(([^)]+)\)')
        foreach ($m in $linkMatches) {
            $target = $m.Groups[1].Value
            if ($target -match '^https?://') { continue }
            if ($target -match '^mailto:') { continue }
            if ($target.StartsWith('#')) { continue }
            $pathPart = $target
            $hashIdx = $pathPart.IndexOf('#')
            if ($hashIdx -ge 0) { $pathPart = $pathPart.Substring(0, $hashIdx) }
            if ([string]::IsNullOrWhiteSpace($pathPart)) { continue }
            $pathPart = $pathPart.TrimEnd('/')
            $resolved = Join-Path $dir $pathPart
            $checked++
            if (-not (Test-Path $resolved)) {
                Add-Error "cited-path: $rel references '$pathPart' which does not exist on disk"
                $missing++
            }
        }
    }
    Add-Check "cited-paths: $checked path link(s) checked, $missing missing"
}

# --- JSON data validation (lightweight structural schema check) -----------
function Test-DataFiles {
    if (-not (Test-Path $DataDir)) {
        Add-Check "data: no docs/data directory (L5 not used)"
        return
    }
    $dataFiles = @(Get-ChildItem -Path $DataDir -Filter '*.json' -File)
    if ($dataFiles.Count -eq 0) {
        Add-Check "data: no L5 json files present"
        return
    }
    $allIds = @{}
    foreach ($df in $dataFiles) {
        $rel = $df.FullName.Substring($RepoRoot.Length).TrimStart('\', '/')
        try {
            $obj = Read-AllText $df.FullName | ConvertFrom-Json
        } catch {
            Add-Error "data: $rel is not valid JSON ($($_.Exception.Message))"
            continue
        }
        Test-JsonFrontMatter $obj $rel

        # Match a schema file by convention: <singular>.schema.json in _schema.
        # exposure_types.json -> exposure_type.schema.json
        $base = [System.IO.Path]::GetFileNameWithoutExtension($df.Name)
        $singular = $base -replace 's$', ''
        $schemaPath = Join-Path $SchemaDir "$singular.schema.json"
        if (-not (Test-Path $schemaPath)) {
            Add-Error "data: $rel has no matching schema (_schema/$singular.schema.json)"
        } else {
            try { $null = Read-AllText $schemaPath | ConvertFrom-Json }
            catch { Add-Error "data: schema _schema/$singular.schema.json is not valid JSON" }
        }

        # Entity ids: present + unique across all data files.
        if ($obj.PSObject.Properties.Name -contains 'entities') {
            foreach ($e in $obj.entities) {
                if (-not ($e.PSObject.Properties.Name -contains 'id')) {
                    Add-Error "data: $rel has an entity with no 'id'"
                    continue
                }
                if ($allIds.ContainsKey($e.id)) {
                    Add-Error "data: duplicate entity id '$($e.id)' (in $rel and $($allIds[$e.id]))"
                } else {
                    $allIds[$e.id] = $rel
                }
            }
        }
    }
    Add-Check "data: $($dataFiles.Count) L5 file(s), $($allIds.Count) entity id(s), all unique"
}

# --- A 'done'-marked story must name a test token; the test should exist ----
function Test-StoryTests {
    if (-not (Test-Path $StoriesPath)) { return }
    $text = Read-AllText $StoriesPath
    $lines = $text -split "\r?\n"
    # Reference status glyphs by code point so this script's own bytes stay
    # ASCII-safe regardless of how PowerShell 5.1 decodes the file. Note:
    # 0x1F7E1 is outside the BMP, so use ConvertFromUtf32 (a [char] cast would
    # overflow System.Char).
    $sDone    = [char]::ConvertFromUtf32(0x2705)
    $sPartial = [char]::ConvertFromUtf32(0x1F7E1)
    $sPlanned = [char]::ConvertFromUtf32(0x2B1C)
    $sCut     = [char]::ConvertFromUtf32(0x1F5D1)
    $doneCount = 0; $partial = 0; $planned = 0; $cut = 0
    $tokens = New-Object System.Collections.Generic.List[string]
    # Only true status-bearing story bullets count: a list item that bolds a
    # story ID followed by exactly one status glyph, e.g.
    #   - **FOAC-US-A1 <glyph>** As a ...
    # This excludes the legend, prose, and the "-> done" backlog references so
    # the status index and the done-needs-a-test check don't false-positive.
    $storyLine = [regex]'^\s*-\s+\*\*[A-Z]+-US-[A-Za-z0-9]+\s+(\S+)\*\*'
    foreach ($ln in $lines) {
        $m = $storyLine.Match($ln)
        if (-not $m.Success) { continue }
        $glyph = $m.Groups[1].Value
        if     ($glyph.Contains($sDone))    { $doneCount++ }
        elseif ($glyph.Contains($sPartial)) { $partial++ }
        elseif ($glyph.Contains($sPlanned)) { $planned++ }
        elseif ($glyph.Contains($sCut))     { $cut++ }
        if ($glyph.Contains($sDone)) {
            # Must cite a test token in backticks, e.g. (verified by `XyzTests`).
            if ($ln -match 'verified by\s+`([^`]+)`') {
                $tokens.Add($matches[1])
            } else {
                Add-Error "stories: done-marked story does not name its verifying test: $($ln.Trim())"
            }
        }
    }
    # Best-effort: each cited token should appear somewhere in the test tree.
    if ($tokens.Count -gt 0) {
        $srcFiles = @(Get-ChildItem -Path $RepoRoot -Recurse -File -Include '*.cs' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '[\\/](obj|bin)[\\/]' })
        foreach ($tok in $tokens) {
            $found = $false
            foreach ($sf in $srcFiles) {
                if ((Read-AllText $sf.FullName).Contains($tok)) { $found = $true; break }
            }
            if (-not $found) {
                Add-Warning "stories: test token '$tok' cited by a done-marked story not found in the test tree"
            }
        }
    }
    Add-Check "stories: $doneCount done / $partial partial / $planned planned / $cut cut (each done names a test)"
    return [pscustomobject]@{ Done = $doneCount; Partial = $partial; Planned = $planned; Cut = $cut }
}

# --- generatedFrom freshness ----------------------------------------------
function Test-DigestFreshness {
    if (-not (Test-Path $DigestPath)) {
        Add-Warning "digest: docs/BIBLE.digest.md is missing — run 'codex.ps1 digest'"
        return
    }
    $expected = Build-DigestText
    $current = Read-AllText $DigestPath
    if ((Normalize $expected) -ne (Normalize $current)) {
        Add-Warning "digest: docs/BIBLE.digest.md is out of date — run 'codex.ps1 digest' to regenerate"
    } else {
        Add-Check "digest: BIBLE.digest.md is current"
    }
    # mtime staleness vs declared source (BIBLE.md / AMENDMENTS.md).
    $digestM = (Get-Item $DigestPath).LastWriteTimeUtc
    foreach ($src in @($BiblePath, $AmendPath)) {
        if (Test-Path $src) {
            $srcM = (Get-Item $src).LastWriteTimeUtc
            if ($srcM -gt $digestM) {
                Add-Warning ("digest: source {0} is newer than the digest (regenerate)" -f (Split-Path -Leaf $src))
            }
        }
    }
}

function Normalize([string]$s) {
    return ($s -replace "\r?\n", "`n").TrimEnd()
}

# --- Section extraction for the digest ------------------------------------
function Get-BibleSection([string]$bibleText, [string]$anchor) {
    # Capture from the heading carrying {#anchor} to the next '## ' heading.
    $lines = $bibleText -split "\r?\n"
    $out = New-Object System.Collections.Generic.List[string]
    $inSection = $false
    foreach ($ln in $lines) {
        if ($ln -match '^##\s' ) {
            if ($inSection) { break }
            if ($ln -match [regex]::Escape("{#$anchor}")) { $inSection = $true; $out.Add($ln); continue }
        }
        if ($inSection) { $out.Add($ln) }
    }
    return ($out -join "`n").TrimEnd()
}

function Build-DigestText {
    $bible = Read-AllText $BiblePath
    $fm = Get-FrontMatter $BiblePath
    $project = if ($fm -and $fm.ContainsKey('project')) { $fm['project'] } else { 'FractionsOfACent' }
    $code = if ($fm -and $fm.ContainsKey('code')) { $fm['code'] } else { 'FOAC' }

    $s1 = Get-BibleSection $bible 'FOAC-§1'
    $s3 = Get-BibleSection $bible 'FOAC-§3'
    $s5 = Get-BibleSection $bible 'FOAC-§5'
    $s9 = Get-BibleSection $bible 'FOAC-§9'

    # Status index from stories.
    $statusLine = 'n/a'
    if (Test-Path $StoriesPath) {
        $sDone    = [char]::ConvertFromUtf32(0x2705)
        $sPartial = [char]::ConvertFromUtf32(0x1F7E1)
        $sPlanned = [char]::ConvertFromUtf32(0x2B1C)
        $sCut     = [char]::ConvertFromUtf32(0x1F5D1)
        $storyLine = [regex]'^\s*-\s+\*\*[A-Z]+-US-[A-Za-z0-9]+\s+(\S+)\*\*'
        $d = 0; $p = 0; $pl = 0; $c = 0
        foreach ($ln in ((Read-AllText $StoriesPath) -split "\r?\n")) {
            $mm = $storyLine.Match($ln)
            if (-not $mm.Success) { continue }
            $g = $mm.Groups[1].Value
            if     ($g.Contains($sDone))    { $d++ }
            elseif ($g.Contains($sPartial)) { $p++ }
            elseif ($g.Contains($sPlanned)) { $pl++ }
            elseif ($g.Contains($sCut))     { $c++ }
        }
        $statusLine = "$d done / $p partial / $pl planned / $c cut"
    }

    # Latest amendment head (first '## ' line in AMENDMENTS.md).
    $amendHead = '(none)'
    if (Test-Path $AmendPath) {
        $al = (Read-AllText $AmendPath) -split "\r?\n"
        foreach ($ln in $al) { if ($ln -match '^##\s+(.+)$') { $amendHead = $matches[1].Trim(); break } }
    }

    $today = (Get-Date).ToString('yyyy-MM-dd')

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("AUTHORITATIVE — full detail in docs/BIBLE.md")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("# $project ($code) — Bible Digest")
    [void]$sb.AppendLine("> Generated by tools/codex.ps1 from docs/BIBLE.md (sections 1, 3, 5, 9). generatedFrom: FOAC-§1,FOAC-§3,FOAC-§5,FOAC-§9. Do not hand-edit.")
    [void]$sb.AppendLine("> Regenerated: $today")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("**Status index:** $statusLine")
    [void]$sb.AppendLine("**Latest amendment:** $amendHead")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine($s1); [void]$sb.AppendLine("")
    [void]$sb.AppendLine($s3); [void]$sb.AppendLine("")
    [void]$sb.AppendLine($s5); [void]$sb.AppendLine("")
    [void]$sb.AppendLine($s9)
    return $sb.ToString()
}

# --- Commands --------------------------------------------------------------
function Invoke-Digest {
    if (-not (Test-Path $BiblePath)) { throw "BIBLE.md not found at $BiblePath" }
    $text = Build-DigestText
    # Write UTF-8 without BOM, LF line endings.
    $norm = ($text -replace "`r`n", "`n")
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($DigestPath, $norm, $enc)
    Write-Host "digest: wrote docs/BIBLE.digest.md ($([System.Text.Encoding]::UTF8.GetByteCount($norm)) bytes)" -ForegroundColor Green
}

function Invoke-Doctor {
    Write-Host "codex doctor — FractionsOfACent" -ForegroundColor Cyan
    Write-Host ("repo: {0}" -f $RepoRoot)
    Write-Host ""

    if (-not (Test-Path $BiblePath))   { Add-Error "missing docs/BIBLE.md" }
    if (-not (Test-Path $StoriesPath)) { Add-Error "missing docs/USER_STORIES.md" }
    if (-not (Test-Path $AmendPath))   { Add-Error "missing docs/AMENDMENTS.md" }

    if (Test-Path $BiblePath)   { Test-FrontMatter $BiblePath   'bible' }
    if (Test-Path $StoriesPath) { Test-FrontMatter $StoriesPath 'stories' }
    if (Test-Path $AmendPath)   { Test-FrontMatter $AmendPath   'amendments' }
    if (Test-Path $RfcDir) {
        foreach ($rfc in (Get-ChildItem -Path $RfcDir -Filter '*.md' -File)) {
            Test-FrontMatter $rfc.FullName 'rfc'
        }
    }

    Test-AnchorsAndRefs
    Test-CitedPaths
    Test-DataFiles
    $null = Test-StoryTests
    Test-DigestFreshness

    Write-Host "Checklist:" -ForegroundColor Cyan
    foreach ($c in $script:Checks) { Write-Host "  [ok]   $c" -ForegroundColor DarkGreen }
    foreach ($w in $script:Warnings) { Write-Host "  [warn] $w" -ForegroundColor Yellow }
    foreach ($e in $script:Errors) { Write-Host "  [FAIL] $e" -ForegroundColor Red }

    Write-Host ""
    if ($script:Errors.Count -gt 0) {
        Write-Host ("doctor: FAILED with {0} error(s), {1} warning(s)" -f $script:Errors.Count, $script:Warnings.Count) -ForegroundColor Red
        exit 1
    }
    Write-Host ("doctor: PASSED ({0} warning(s))" -f $script:Warnings.Count) -ForegroundColor Green
    exit 0
}

switch ($Command) {
    'digest' { Invoke-Digest }
    'doctor' { Invoke-Doctor }
}
