# FractionsOfAPenny

A leaked-credential prevalence scanner for public GitHub repositories,
built as a research artifact for a Masters thesis in Cybersecurity.
Targets API keys for Anthropic (Claude), OpenAI (GPT / o-series), and
Google (Gemini), recording **metadata only** — the keys themselves are
never persisted, logged, or returned from any function.

## Why this exists

Leaked LLM API keys on GitHub are an active abuse vector: attackers
harvest them to run free inference on the victim's account, run up
bills, exfiltrate prompts, or proxy them to downstream consumers. The
providers all run coordinated secret-scanning with GitHub, but the
population of leaks — how many, where, in what languages, tied to which
models, with what time-to-revocation — is under-measured compared to
generic cloud credentials.

This project produces a defensible dataset for that measurement without
ever holding the credentials it detects.

## Research ethics and scope

- **Scope**: public repositories indexed by GitHub Code Search. No
  private data, no authenticated-only endpoints, no cloning, no
  execution of repo code.
- **Non-retention** is enforced at the code level. Python:
  [python/scraper.py:145-168](python/scraper.py). C#:
  [csharp/Scraper.cs:82-111](csharp/Scraper.cs). The raw regex match is bound
  to a local variable, used to compute a SHA-256 and a 16-character
  non-sensitive prefix (scheme marker only, e.g. `sk-ant-api03-XYZ`),
  then drops out of scope. It is never written to disk, emitted to
  logs, serialized, or returned from a function.
- **No validation**: the tool does not call the provider APIs with any
  detected key. Liveness is inferred from public signals (GitHub's
  secret-scanning response, provider revocation notices), not
  authenticated probes.
- **Responsible disclosure**: every finding should be forwarded to the
  provider's secret-scanning or security intake (see
  [python/disclosure.py](python/disclosure.py)) so the key is revoked. GitHub's push
  protection already auto-revokes for these three providers, so the
  dataset also serves to measure that system's coverage.

## Methodology precedent

This design follows the hash-and-discard methodology established by:

> Meli, M., McNiece, M. R., & Reaves, B. (2019).
> *How Bad Can It Git? Characterizing Secret Leakage in Public GitHub
> Repositories.*
> Network and Distributed System Security Symposium (NDSS).
> <https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/>

Meli et al. scanned ~13% of GitHub's public contents for secrets,
recording cryptographic fingerprints rather than the secrets themselves,
and published aggregate statistics. The prefix-plus-hash approach here
is the same: it lets you deduplicate across forks and commit history
(the same key committed to twenty forks is one unique leaker, not
twenty) without the artifact ever becoming a credential wallet.

For your IRB / thesis-committee record, the non-retention property is
auditable in the source — reviewers can run the scanner against a repo
they control with a decoy key format and verify that `findings.json`
contains only the hash, never the key.

## What each finding records

| Field | Purpose |
|---|---|
| `provider` | anthropic \| openai \| openai-legacy \| google-gemini |
| `model_hint` | Nearest model name within 200 chars of the match |
| `repo_full_name`, `repo_html_url` | Which repo leaked |
| `author_login` | Repo owner login |
| `file_path`, `file_html_url` | Where in the repo |
| `commit_sha`, `default_branch` | Reproducibility handle |
| `detected_at_utc` | When we observed it |
| `key_sha256` | Deduplication fingerprint (non-reversible) |
| `key_prefix` | First ≤16 chars — scheme marker only, not auth |
| `key_length` | Aids pattern-drift analysis |

## Repository layout

```
FractionsOfAPenny/
├── python/             # Python implementation
│   ├── scraper.py
│   ├── patterns.py     # Provider regex + model hints
│   ├── disclosure.py   # Per-provider intake summary
│   ├── report.py       # HTML report renderer
│   └── requirements.txt
└── csharp/             # C# / .NET 9 console app (same semantics)
    ├── Program.cs
    ├── Scraper.cs
    ├── GitHubClient.cs
    ├── Patterns.cs
    ├── Finding.cs
    ├── Settings.cs
    ├── Report.cs       # HTML report renderer
    └── FractionsOfAPenny.csproj
```

Both read the GitHub PAT from (in order):

1. `GITHUB_TOKEN` env var
2. `%APPDATA%\MindAttic\FractionsOfAPenny\settings.json` on Windows, or
   `~/.config/MindAttic/FractionsOfAPenny/settings.json` on macOS/Linux:

   ```json
   { "github_token": "github_pat_..." }
   ```

This config file lives outside the repo and is never committed.

## Running

### Python

```bash
cd python
pip install -r requirements.txt
export GITHUB_TOKEN=ghp_xxx           # or populate settings.json (see above)
python scraper.py --out ../findings.json --max-per-provider 50
python disclosure.py ../findings.json
```

### C#

```bash
cd csharp
dotnet build
export GITHUB_TOKEN=ghp_xxx           # or populate settings.json (see above)
dotnet run -- --out ../findings.json --max-per-provider 50
```

Both binaries accept `--provider anthropic` (repeatable) to narrow to a
single provider, and both append to an existing `findings.json`,
deduplicating by `(key_sha256, repo_full_name, file_path)` — a key
stable across indexing-time commit SHAs. Each run also writes a
`findings.htm` report next to the JSON file.

## Thesis-worthy analyses supported by the dataset

- Leak rate per 1k indexed files, per provider, over time.
- Model-family distribution — what models developers are actually using
  in the code that also leaks the key.
- File-type and language distribution (`.env`, `.ipynb`, `config.js`,
  hard-coded vs. dotenv loads).
- Time-to-revocation: detection timestamp vs. when the key stops
  appearing in fresh scans (proxy for provider revocation).
- Before/after measurement of GitHub's push-protection coverage
  expansion.
- Fork amplification: for a single unique `key_sha256`, how many
  distinct repos carry it (copy-paste vs. forks vs. re-commits).

## What this tool does NOT do

- It does not retrieve or retain API keys.
- It does not validate keys against provider APIs.
- It does not scrape private repos, commits behind auth, or GitHub
  Enterprise.
- It does not evade GitHub rate limits or terms of service.
- It is not a pentest or offensive-security tool. It is measurement.
