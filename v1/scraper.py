"""
FractionsOfACent — leaked-credential prevalence scanner.

Academic research tool. Collects METADATA ONLY about public GitHub repos
that have committed LLM API keys. Raw keys are never written to disk,
logged, or returned from functions. Each match is identified by the
SHA-256 of the key and a 6-character prefix (for provider confirmation),
which are not usable as credentials.

Usage:
    export GITHUB_TOKEN=ghp_xxx   # or populate settings.json under %APPDATA%
    cd python && python scraper.py --out ../findings.db --max-per-provider 100

State is persisted in SQLite (--out path). Re-runs skip any (repo, file)
already pulled in a previous run, so successive runs add only genuinely
new findings. The HTML report next to the DB is regenerated each run
from the full DB and grows monotonically.

Responsible-use checklist:
  - Run under IRB/department approval only.
  - Submit findings to the provider's secret-scanning intake (see
    disclosure.py) so keys are revoked. Do not test or use any key.
  - Throttle aggressively. GitHub Code Search allows ~30 req/min
    authenticated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator

import requests

import db
from patterns import PATTERNS, ProviderPattern, infer_model
from report import write as write_report

GITHUB_API = "https://api.github.com"
USER_AGENT = "fractions-of-a-cent-research/0.1 (+academic study, metadata-only)"
CONTEXT_RADIUS = 200  # chars around the match used for model-name inference
log = logging.getLogger("fractions")


def settings_path() -> Path:
    """
    Per-user config location, shared with the C# scraper.
    Windows: %APPDATA%\\MindAttic\\FractionsOfACent\\settings.json
    macOS/Linux: ~/.config/MindAttic/FractionsOfACent/settings.json
    """
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "MindAttic" / "FractionsOfACent" / "settings.json"


def load_token() -> str | None:
    """
    Resolve the GitHub PAT. Env var wins so CI and ad-hoc overrides work;
    otherwise read from the per-user settings.json (shared with the C# scraper).
    """
    env = os.environ.get("GITHUB_TOKEN")
    if env:
        return env
    path = settings_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    tok = data.get("github_token")
    return tok if isinstance(tok, str) and tok.strip() else None


@dataclass
class Finding:
    """
    One metadata record per detected leak. No raw key is stored.
    Timestamps are owned by the DB (first_seen_utc / last_seen_utc).
    """

    provider: str
    model_hint: str | None
    repo_full_name: str
    repo_url: str
    repo_html_url: str
    author_login: str | None
    file_path: str
    file_html_url: str
    commit_sha: str | None
    default_branch: str | None
    # Non-reversible fingerprints for deduplication and provider
    # confirmation. The prefix is the literal scheme marker (e.g.
    # "sk-ant-") plus three characters — insufficient to authenticate.
    key_sha256: str
    key_prefix: str
    key_length: int


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }


def _sleep_for_ratelimit(resp: requests.Response) -> None:
    """Back off until the Code Search secondary rate limit resets."""
    remaining = resp.headers.get("X-RateLimit-Remaining")
    reset = resp.headers.get("X-RateLimit-Reset")
    if remaining == "0" and reset:
        wait = max(1, int(reset) - int(time.time()) + 1)
        log.warning("rate limited; sleeping %ds", wait)
        time.sleep(wait)


def search_code(
    token: str,
    needle: str,
    per_page: int = 30,
    max_pages: int = 10,
) -> Iterator[dict]:
    """
    Yield GitHub Code Search hits for a literal needle.
    Code Search caps results at 1000. We page until exhausted or capped.
    """
    for page in range(1, max_pages + 1):
        params = {
            "q": f"{needle} in:file",
            "per_page": per_page,
            "page": page,
        }
        resp = requests.get(
            f"{GITHUB_API}/search/code",
            headers=_headers(token),
            params=params,
            timeout=30,
        )
        if resp.status_code == 403:
            _sleep_for_ratelimit(resp)
            continue
        if resp.status_code == 422:
            # "Only the first 1000 search results are available"
            return
        resp.raise_for_status()
        items = resp.json().get("items", [])
        if not items:
            return
        yield from items
        # Courtesy delay between pages (Code Search is strict).
        time.sleep(2)


def fetch_file_text(token: str, item: dict) -> tuple[str, str | None, str | None]:
    """
    Return (content, commit_sha, default_branch) for a code-search hit.
    Content is read and must be discarded by the caller once scanned.
    """
    download_url = item.get("html_url", "").replace(
        "github.com", "raw.githubusercontent.com"
    ).replace("/blob/", "/")
    # Prefer the REST contents API so we get the exact sha/ref.
    contents_url = item["url"]  # .../repos/{owner}/{repo}/contents/{path}?ref=...
    resp = requests.get(
        contents_url, headers=_headers(token), timeout=30
    )
    if resp.status_code == 403:
        _sleep_for_ratelimit(resp)
        return "", None, None
    if not resp.ok:
        return "", None, None
    payload = resp.json()
    import base64

    raw = ""
    if payload.get("encoding") == "base64" and payload.get("content"):
        try:
            raw = base64.b64decode(payload["content"]).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            raw = ""
    commit_sha = payload.get("sha")
    default_branch = item.get("repository", {}).get("default_branch")
    return raw, commit_sha, default_branch


def fingerprint(key: str) -> tuple[str, str, int]:
    """
    Return (sha256_hex, non-sensitive_prefix, length).
    The prefix is the scheme marker + 3 chars — not usable for auth.
    """
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()
    # For sk-ant-api03-XYZ..., prefix is "sk-ant-api03-XYZ" truncated short.
    prefix_end = min(len(key), key.find("-", key.find("-") + 1) + 4)
    prefix = key[: max(6, prefix_end)] if prefix_end > 0 else key[:6]
    return h, prefix[:16], len(key)


def scan_item(
    token: str, item: dict, pat: ProviderPattern
) -> list[Finding]:
    """
    Scan one code-search hit. Returns metadata-only findings.
    The raw key is bound to a local var, used to compute the hash,
    then goes out of scope without ever being serialized or logged.
    """
    content, commit_sha, default_branch = fetch_file_text(token, item)
    if not content:
        return []

    findings: list[Finding] = []
    seen_hashes: set[str] = set()
    for m in pat.regex.finditer(content):
        raw_key = m.group(0)
        key_hash, prefix, key_len = fingerprint(raw_key)
        if key_hash in seen_hashes:
            continue
        seen_hashes.add(key_hash)

        start, end = m.span()
        context = content[
            max(0, start - CONTEXT_RADIUS) : min(len(content), end + CONTEXT_RADIUS)
        ]
        model = infer_model(context, pat.model_hints)

        repo = item.get("repository", {})
        findings.append(
            Finding(
                provider=pat.provider,
                model_hint=model,
                repo_full_name=repo.get("full_name", ""),
                repo_url=repo.get("url", ""),
                repo_html_url=repo.get("html_url", ""),
                author_login=(repo.get("owner") or {}).get("login"),
                file_path=item.get("path", ""),
                file_html_url=item.get("html_url", ""),
                commit_sha=commit_sha,
                default_branch=default_branch,
                key_sha256=key_hash,
                key_prefix=prefix,
                key_length=key_len,
            )
        )
        # Explicitly clear the reference. Python may keep it in the
        # regex match object until GC, so we also drop m below.
        del raw_key
    del content
    return findings


def run(
    token: str,
    db_path: Path,
    max_per_provider: int,
    providers: list[str] | None,
) -> int:
    con = db.connect(db_path)
    try:
        imported = db.maybe_import_legacy(con, db_path)
        if imported:
            log.info(
                "imported %d records from legacy %s", imported,
                db_path.with_suffix(".json"),
            )

        before = db.stats(con)
        log.info(
            "db state at start: findings=%d scanned_files=%d",
            before["findings"], before["scanned_files"],
        )

        total_new = 0
        for pat in PATTERNS:
            if providers and pat.provider not in providers:
                continue
            log.info("scanning provider=%s needle=%r", pat.provider, pat.search_needle)
            found_for_provider = 0
            skipped = 0
            for item in search_code(token, pat.search_needle):
                if found_for_provider >= max_per_provider:
                    break
                repo = (item.get("repository") or {}).get("full_name") or ""
                path = item.get("path") or ""
                if not repo or not path:
                    continue
                # Atomic claim: if a concurrent scraper already grabbed
                # this file, skip without fetching.
                with con:
                    claimed = db.claim_scan(con, repo, path)
                if not claimed:
                    skipped += 1
                    continue
                try:
                    file_findings = scan_item(token, item, pat)
                    with con:
                        first_sha = (
                            file_findings[0].commit_sha if file_findings else None
                        )
                        db.record_commit_for_scan(con, repo, path, first_sha)
                        for finding in file_findings:
                            if db.upsert_finding(con, asdict(finding)):
                                total_new += 1
                                found_for_provider += 1
                                log.info(
                                    "  %s %s#%s (%s)",
                                    finding.provider,
                                    finding.repo_full_name,
                                    finding.file_path,
                                    finding.model_hint or "model=?",
                                )
                                if found_for_provider >= max_per_provider:
                                    break
                except requests.HTTPError as e:
                    log.warning("fetch failed: %s", e)
                # Courtesy pacing against the contents API.
                time.sleep(0.5)

            log.info(
                "provider=%s new=%d skipped(already-scanned)=%d total_new=%d",
                pat.provider, found_for_provider, skipped, total_new,
            )

        records = db.all_findings(con)
        html_path = write_report(records, db_path)
        after = db.stats(con)
        log.info(
            "done. new findings: %d, total in db: %d, scanned_files: %d",
            total_new, after["findings"], after["scanned_files"],
        )
        log.info("wrote report: %s", html_path)
        return total_new
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("findings.db"),
        help="SQLite database path (sibling .htm report is regenerated each run)",
    )
    parser.add_argument(
        "--max-per-provider",
        type=int,
        default=50,
        help="stop after N findings per provider per run",
    )
    parser.add_argument(
        "--provider",
        action="append",
        choices=[p.provider for p in PATTERNS],
        help="limit to one or more providers (repeatable)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="debug logging"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    token = load_token()
    if not token:
        print(
            "error: GitHub PAT not found. Set GITHUB_TOKEN, or put\n"
            '  { "github_token": "github_pat_..." }\n'
            f"  into {settings_path()}\n"
            "(fine-grained PAT with public-repo read is enough).",
            file=sys.stderr,
        )
        return 2

    run(token, args.out, args.max_per_provider, args.provider)
    return 0


if __name__ == "__main__":
    sys.exit(main())
