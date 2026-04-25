"""
SQLite persistence for FractionsOfACent.

The database is the source of truth across runs:
  - findings: deduplicated by (key_sha256, repo_full_name, file_path).
    first_seen_utc is preserved across re-runs; last_seen_utc bumps each
    time the same leak is observed.
  - scanned_files: every (repo, path) the scraper has already pulled
    from the contents API, so re-runs skip them entirely instead of
    burning rate-limit and re-fetching the same 1000-result page.

No raw API keys are persisted. Only the SHA-256 hash and 16-char scheme
prefix already produced by scraper.fingerprint() are stored.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
-- Exposure category lookup. auto_inform controls whether the CLI
-- auto-notify pass is allowed to file an issue against a repo when a
-- finding of this type is detected. Default 0 (false) so review-then-act
-- is the safe default; user flips it on in the Web UI when confident.
CREATE TABLE IF NOT EXISTS exposure_types (
  name         TEXT PRIMARY KEY,
  description  TEXT,
  auto_inform  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
  key_sha256       TEXT NOT NULL,
  repo_full_name   TEXT NOT NULL,
  file_path        TEXT NOT NULL,
  provider         TEXT NOT NULL,
  exposure_type    TEXT NOT NULL DEFAULT 'ApiKey'
    REFERENCES exposure_types(name),
  model_hint       TEXT,
  repo_url         TEXT,
  repo_html_url    TEXT,
  author_login     TEXT,
  file_html_url    TEXT,
  commit_sha       TEXT,
  default_branch   TEXT,
  key_prefix       TEXT,
  key_length       INTEGER,
  first_seen_utc   TEXT NOT NULL,
  last_seen_utc    TEXT NOT NULL,
  PRIMARY KEY (key_sha256, repo_full_name, file_path)
);

CREATE INDEX IF NOT EXISTS findings_provider_idx ON findings(provider);
CREATE INDEX IF NOT EXISTS findings_repo_idx     ON findings(repo_full_name);
CREATE INDEX IF NOT EXISTS findings_author_idx   ON findings(author_login);
CREATE INDEX IF NOT EXISTS findings_type_idx     ON findings(exposure_type);

CREATE TABLE IF NOT EXISTS scanned_files (
  repo_full_name   TEXT NOT NULL,
  file_path        TEXT NOT NULL,
  commit_sha       TEXT,
  scanned_at_utc   TEXT NOT NULL,
  PRIMARY KEY (repo_full_name, file_path)
);

-- One row per (finding, channel). Records the takedown notice we sent
-- the repo owner. status: 'sent' | 'failed' | 'skipped'.
CREATE TABLE IF NOT EXISTS notices (
  key_sha256       TEXT NOT NULL,
  repo_full_name   TEXT NOT NULL,
  file_path        TEXT NOT NULL,
  channel          TEXT NOT NULL,
  issue_number     INTEGER,
  issue_html_url   TEXT,
  sent_at_utc      TEXT NOT NULL,
  status           TEXT NOT NULL,
  error            TEXT,
  PRIMARY KEY (key_sha256, repo_full_name, file_path, channel)
);

CREATE INDEX IF NOT EXISTS notices_repo_idx ON notices(repo_full_name);

-- Append-only history of remediation rechecks. The latest row per
-- finding gives the current presence/absence; the full series is the
-- time-to-revocation signal for the thesis. status:
-- 'present' | 'removed' | 'file_gone' | 'repo_gone' | 'fetch_failed'.
CREATE TABLE IF NOT EXISTS remediation_checks (
  key_sha256       TEXT NOT NULL,
  repo_full_name   TEXT NOT NULL,
  file_path        TEXT NOT NULL,
  checked_at_utc   TEXT NOT NULL,
  status           TEXT NOT NULL,
  commit_sha       TEXT,
  PRIMARY KEY (key_sha256, repo_full_name, file_path, checked_at_utc)
);

CREATE INDEX IF NOT EXISTS remediation_checks_finding_idx
  ON remediation_checks(key_sha256, repo_full_name, file_path);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


EXPOSURE_TYPES_SEED = (
    ("ApiKey",
     "Provider-issued API token (LLM, cloud, payments, communications, package registries, version control)."),
    ("ConnectionString",
     "Database / cache / message-broker URI containing inline username:password credentials."),
    ("PrivateKey",
     "PEM-encoded private key block (RSA, DSA, EC, OpenSSH, PGP)."),
    ("PlainTextPassword",
     "Variable assignment to a string literal under a name like 'password', 'passwd', 'secret', or 'pwd'. High false-positive rate; opt-in scan only."),
)


def _has_column(con: sqlite3.Connection, table: str, column: str) -> bool:
    cur = con.execute(f"PRAGMA table_info({table})")
    return any(row[1].lower() == column.lower() for row in cur.fetchall())


def connect(path: Path) -> sqlite3.Connection:
    """
    Open the DB with concurrency-safe pragmas. WAL allows the C# scraper
    and the Python scraper to write simultaneously without serializing on
    a single global lock; busy_timeout makes brief lock contention retry
    instead of raising SQLITE_BUSY.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA busy_timeout=5000")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript(SCHEMA)

    # Idempotent migration: pre-exposure_type DBs need the column added.
    if not _has_column(con, "findings", "exposure_type"):
        con.execute(
            "ALTER TABLE findings ADD COLUMN exposure_type TEXT NOT NULL "
            "DEFAULT 'ApiKey'"
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS findings_type_idx ON findings(exposure_type)"
        )

    # Seed canonical types. Description is refreshed on every run; the
    # auto_inform value is preserved so the user's review-then-act
    # preference survives across runs.
    for name, description in EXPOSURE_TYPES_SEED:
        con.execute(
            """
            INSERT INTO exposure_types (name, description, auto_inform)
            VALUES (?, ?, 0)
            ON CONFLICT(name) DO UPDATE SET description = excluded.description
            """,
            (name, description),
        )
    con.commit()
    return con


def is_scanned(con: sqlite3.Connection, repo: str, path: str) -> bool:
    return (
        con.execute(
            "SELECT 1 FROM scanned_files WHERE repo_full_name=? AND file_path=?",
            (repo, path),
        ).fetchone()
        is not None
    )


def claim_scan(con: sqlite3.Connection, repo: str, path: str) -> bool:
    """
    Atomically claim a (repo, path) for scanning. Returns True iff this
    caller won the race; False if another scraper already claimed it.

    The claim is permanent once granted — even if the subsequent fetch
    fails, the row stays so we don't re-attempt forever. To force a
    rescan, delete from scanned_files.
    """
    cur = con.execute(
        """
        INSERT OR IGNORE INTO scanned_files
            (repo_full_name, file_path, commit_sha, scanned_at_utc)
        VALUES (?, ?, NULL, ?)
        """,
        (repo, path, _now()),
    )
    return cur.rowcount > 0


def record_commit_for_scan(
    con: sqlite3.Connection, repo: str, path: str, commit_sha: str | None
) -> None:
    """Backfill the commit_sha after a successful fetch."""
    con.execute(
        """
        UPDATE scanned_files
           SET commit_sha = ?, scanned_at_utc = ?
         WHERE repo_full_name = ? AND file_path = ?
        """,
        (commit_sha, _now(), repo, path),
    )


def mark_scanned(
    con: sqlite3.Connection, repo: str, path: str, commit_sha: str | None
) -> None:
    """
    Compatibility helper for the legacy importer. Use claim_scan +
    record_commit_for_scan in the live scraper instead.
    """
    con.execute(
        """
        INSERT INTO scanned_files
            (repo_full_name, file_path, commit_sha, scanned_at_utc)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(repo_full_name, file_path) DO UPDATE SET
            commit_sha = excluded.commit_sha,
            scanned_at_utc = excluded.scanned_at_utc
        """,
        (repo, path, commit_sha, _now()),
    )


def upsert_finding(
    con: sqlite3.Connection,
    f: dict,
    *,
    first_seen_utc: str | None = None,
) -> bool:
    """
    Insert a finding keyed on (key_sha256, repo_full_name, file_path).
    Returns True iff the row is new. On conflict, last_seen_utc is bumped
    and any newly-known model_hint / commit_sha / default_branch is
    backfilled.
    """
    now = _now()
    first_seen = first_seen_utc or now
    cur = con.execute(
        """
        INSERT OR IGNORE INTO findings (
            key_sha256, repo_full_name, file_path,
            provider, model_hint, repo_url, repo_html_url,
            author_login, file_html_url, commit_sha, default_branch,
            key_prefix, key_length,
            first_seen_utc, last_seen_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f["key_sha256"], f["repo_full_name"], f["file_path"],
            f["provider"], f.get("model_hint"),
            f.get("repo_url"), f.get("repo_html_url"),
            f.get("author_login"), f.get("file_html_url"),
            f.get("commit_sha"), f.get("default_branch"),
            f.get("key_prefix"), f.get("key_length"),
            first_seen, now,
        ),
    )
    if cur.rowcount:
        return True
    con.execute(
        """
        UPDATE findings SET
            last_seen_utc = ?,
            model_hint    = COALESCE(model_hint, ?),
            commit_sha    = COALESCE(?, commit_sha),
            default_branch= COALESCE(?, default_branch)
        WHERE key_sha256=? AND repo_full_name=? AND file_path=?
        """,
        (
            now,
            f.get("model_hint"),
            f.get("commit_sha"),
            f.get("default_branch"),
            f["key_sha256"], f["repo_full_name"], f["file_path"],
        ),
    )
    return False


def all_findings(con: sqlite3.Connection) -> list[dict]:
    rows = con.execute(
        "SELECT * FROM findings ORDER BY first_seen_utc DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def stats(con: sqlite3.Connection) -> dict:
    findings_n = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    scanned_n = con.execute("SELECT COUNT(*) FROM scanned_files").fetchone()[0]
    return {"findings": findings_n, "scanned_files": scanned_n}


def get_notice(
    con: sqlite3.Connection, key_sha256: str, repo: str, path: str, channel: str
) -> dict | None:
    row = con.execute(
        """
        SELECT * FROM notices
         WHERE key_sha256=? AND repo_full_name=?
           AND file_path=? AND channel=?
        """,
        (key_sha256, repo, path, channel),
    ).fetchone()
    return dict(row) if row else None


def insert_remediation_check(
    con: sqlite3.Connection,
    key_sha256: str,
    repo: str,
    path: str,
    status: str,
    commit_sha: str | None,
) -> None:
    con.execute(
        """
        INSERT OR IGNORE INTO remediation_checks (
            key_sha256, repo_full_name, file_path,
            checked_at_utc, status, commit_sha
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (key_sha256, repo, path, _now(), status, commit_sha),
    )


def latest_remediation_checks(
    con: sqlite3.Connection,
) -> dict[tuple[str, str, str], dict]:
    """
    Latest remediation-check row keyed by (key_sha256, repo, file_path).
    Used by the recheck pass to skip findings already in a terminal state.
    """
    rows = con.execute(
        """
        SELECT rc.* FROM remediation_checks rc
        INNER JOIN (
            SELECT key_sha256, repo_full_name, file_path,
                   MAX(checked_at_utc) AS latest
              FROM remediation_checks
             GROUP BY key_sha256, repo_full_name, file_path
        ) latest ON
            rc.key_sha256 = latest.key_sha256
            AND rc.repo_full_name = latest.repo_full_name
            AND rc.file_path = latest.file_path
            AND rc.checked_at_utc = latest.latest
        """
    ).fetchall()
    return {
        (r["key_sha256"], r["repo_full_name"], r["file_path"]): dict(r)
        for r in rows
    }


def maybe_import_legacy(con: sqlite3.Connection, db_path: Path) -> int:
    """
    One-shot migrator. If a sibling findings.json exists and the DB has
    no records yet, import it. Returns count newly inserted.
    """
    legacy = db_path.with_suffix(".json")
    if not legacy.exists():
        return 0
    existing = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    if existing > 0:
        return 0
    try:
        records = json.loads(legacy.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0
    n = 0
    with con:
        for r in records:
            if not r.get("key_sha256") or not r.get("repo_full_name"):
                continue
            if upsert_finding(con, r, first_seen_utc=r.get("detected_at_utc")):
                n += 1
            mark_scanned(
                con,
                r["repo_full_name"],
                r.get("file_path", ""),
                r.get("commit_sha"),
            )
    return n
