using Microsoft.Data.Sqlite;

namespace FractionsOfACent;

/// <summary>
/// SQLite persistence shared with python/db.py. Schema and dedup keys are
/// identical so the C# scraper and the Python scraper can write to the
/// same database concurrently. WAL + busy_timeout makes that race-safe;
/// whichever scraper claims a (repo, file_path) first via mark_scanned
/// makes the other skip it.
///
/// No raw API keys are persisted — only SHA-256 hash + 16-char scheme
/// prefix already produced by Scraper.Fingerprint().
/// </summary>
public sealed class Db : IDisposable
{
    private const string Schema = """
        -- Exposure category lookup. auto_inform controls whether the CLI
        -- auto-notify pass is allowed to file an issue against a repo
        -- when a finding of this type is detected. Default is 0 (false)
        -- so review-then-act is the safe default; the user flips it on
        -- in the Web UI when they're confident in a category's signal.
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

        CREATE INDEX IF NOT EXISTS findings_type_idx ON findings(exposure_type);

        CREATE INDEX IF NOT EXISTS findings_provider_idx ON findings(provider);
        CREATE INDEX IF NOT EXISTS findings_repo_idx     ON findings(repo_full_name);
        CREATE INDEX IF NOT EXISTS findings_author_idx   ON findings(author_login);

        CREATE TABLE IF NOT EXISTS scanned_files (
          repo_full_name   TEXT NOT NULL,
          file_path        TEXT NOT NULL,
          commit_sha       TEXT,
          scanned_at_utc   TEXT NOT NULL,
          PRIMARY KEY (repo_full_name, file_path)
        );

        -- One row per (finding, channel). Records the takedown notice we
        -- sent the repo owner. status: 'sent' | 'failed' | 'skipped'.
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
        -- finding gives the current presence/absence; the full series is
        -- the time-to-revocation signal for the thesis. status:
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
        """;

    private readonly SqliteConnection _con;

    public Db(FileInfo path)
    {
        var dir = path.DirectoryName;
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var cs = new SqliteConnectionStringBuilder
        {
            DataSource = path.FullName,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            DefaultTimeout = 30,
        }.ToString();
        _con = new SqliteConnection(cs);
        _con.Open();

        // Concurrency-safe pragmas. Must match python/db.py.
        Exec("PRAGMA journal_mode=WAL;");
        Exec("PRAGMA synchronous=NORMAL;");
        Exec("PRAGMA busy_timeout=5000;");
        Exec("PRAGMA foreign_keys=ON;");
        Exec(Schema);
        MigrateAddExposureTypeColumn();
        SeedExposureTypes();
    }

    /// <summary>
    /// SQLite ALTER TABLE ADD COLUMN is idempotent-only by way of
    /// PRAGMA table_info; we check first because re-running CREATE TABLE
    /// IF NOT EXISTS leaves the existing table untouched.
    /// </summary>
    private void MigrateAddExposureTypeColumn()
    {
        if (HasColumn("findings", "exposure_type")) return;
        // Older DBs only had ApiKey-style findings; backfill is safe.
        Exec(
            "ALTER TABLE findings ADD COLUMN exposure_type TEXT NOT NULL DEFAULT 'ApiKey';");
        Exec("CREATE INDEX IF NOT EXISTS findings_type_idx ON findings(exposure_type);");
    }

    private bool HasColumn(string table, string column)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info({table});";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            if (string.Equals(r.GetString(1), column, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Insert the canonical exposure types if they're not already there.
    /// auto_inform stays at the existing value if the row already exists,
    /// so the user's review-then-act preference is preserved across runs.
    /// </summary>
    private void SeedExposureTypes()
    {
        foreach (var (name, description) in ExposureTypes.All)
        {
            using var cmd = _con.CreateCommand();
            cmd.CommandText = """
                INSERT INTO exposure_types (name, description, auto_inform)
                VALUES ($n, $d, 0)
                ON CONFLICT(name) DO UPDATE SET description = excluded.description;
                """;
            cmd.Parameters.AddWithValue("$n", name);
            cmd.Parameters.AddWithValue("$d", description);
            cmd.ExecuteNonQuery();
        }
    }

    private static string NowIso() => DateTime.UtcNow.ToString("O");

    private void Exec(string sql)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    public bool IsScanned(string repo, string path)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText =
            "SELECT 1 FROM scanned_files WHERE repo_full_name=$r AND file_path=$p";
        cmd.Parameters.AddWithValue("$r", repo);
        cmd.Parameters.AddWithValue("$p", path);
        return cmd.ExecuteScalar() is not null;
    }

    /// <summary>
    /// Atomically claim a (repo, path) for scanning. Returns true iff this
    /// caller won the race; false if another scraper already claimed it.
    /// The claim is permanent once granted — to force a rescan, delete the
    /// row from scanned_files.
    /// </summary>
    public bool ClaimScan(string repo, string path)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = """
            INSERT OR IGNORE INTO scanned_files
                (repo_full_name, file_path, commit_sha, scanned_at_utc)
            VALUES ($r, $p, NULL, $t);
            """;
        cmd.Parameters.AddWithValue("$r", repo);
        cmd.Parameters.AddWithValue("$p", path);
        cmd.Parameters.AddWithValue("$t", NowIso());
        return cmd.ExecuteNonQuery() > 0;
    }

    public void RecordCommitForScan(string repo, string path, string? commitSha)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = """
            UPDATE scanned_files
               SET commit_sha = $c, scanned_at_utc = $t
             WHERE repo_full_name = $r AND file_path = $p;
            """;
        cmd.Parameters.AddWithValue("$c", (object?)commitSha ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$t", NowIso());
        cmd.Parameters.AddWithValue("$r", repo);
        cmd.Parameters.AddWithValue("$p", path);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Compatibility helper for the legacy importer. Use ClaimScan +
    /// RecordCommitForScan in the live scraper instead.
    /// </summary>
    public void MarkScanned(string repo, string path, string? commitSha)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = """
            INSERT INTO scanned_files
                (repo_full_name, file_path, commit_sha, scanned_at_utc)
            VALUES ($r, $p, $c, $t)
            ON CONFLICT(repo_full_name, file_path) DO UPDATE SET
                commit_sha = excluded.commit_sha,
                scanned_at_utc = excluded.scanned_at_utc;
            """;
        cmd.Parameters.AddWithValue("$r", repo);
        cmd.Parameters.AddWithValue("$p", path);
        cmd.Parameters.AddWithValue("$c", (object?)commitSha ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$t", NowIso());
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Returns true iff the row was newly inserted. On conflict, last_seen_utc
    /// is bumped and any newly-known model_hint / commit_sha / default_branch
    /// is backfilled.
    /// </summary>
    public bool UpsertFinding(Finding f, string? firstSeenOverride = null)
    {
        var now = NowIso();
        var firstSeen = firstSeenOverride ?? now;

        using var insert = _con.CreateCommand();
        insert.CommandText = """
            INSERT OR IGNORE INTO findings (
                key_sha256, repo_full_name, file_path,
                provider, exposure_type, model_hint, repo_url, repo_html_url,
                author_login, file_html_url, commit_sha, default_branch,
                key_prefix, key_length,
                first_seen_utc, last_seen_utc
            ) VALUES (
                $sha, $repo, $path,
                $prov, $etype, $model, $rurl, $rhtml,
                $author, $fhtml, $csha, $branch,
                $kpref, $klen,
                $first, $last
            );
            """;
        insert.Parameters.AddWithValue("$sha", f.KeySha256);
        insert.Parameters.AddWithValue("$repo", f.RepoFullName);
        insert.Parameters.AddWithValue("$path", f.FilePath);
        insert.Parameters.AddWithValue("$prov", f.Provider);
        insert.Parameters.AddWithValue("$etype", f.ExposureType);
        insert.Parameters.AddWithValue("$model", (object?)f.ModelHint ?? DBNull.Value);
        insert.Parameters.AddWithValue("$rurl", f.RepoUrl);
        insert.Parameters.AddWithValue("$rhtml", f.RepoHtmlUrl);
        insert.Parameters.AddWithValue("$author", (object?)f.AuthorLogin ?? DBNull.Value);
        insert.Parameters.AddWithValue("$fhtml", f.FileHtmlUrl);
        insert.Parameters.AddWithValue("$csha", (object?)f.CommitSha ?? DBNull.Value);
        insert.Parameters.AddWithValue("$branch", (object?)f.DefaultBranch ?? DBNull.Value);
        insert.Parameters.AddWithValue("$kpref", f.KeyPrefix);
        insert.Parameters.AddWithValue("$klen", f.KeyLength);
        insert.Parameters.AddWithValue("$first", firstSeen);
        insert.Parameters.AddWithValue("$last", now);

        var inserted = insert.ExecuteNonQuery() > 0;
        if (inserted) return true;

        using var update = _con.CreateCommand();
        update.CommandText = """
            UPDATE findings SET
                last_seen_utc  = $last,
                model_hint     = COALESCE(model_hint, $model),
                commit_sha     = COALESCE($csha, commit_sha),
                default_branch = COALESCE($branch, default_branch)
            WHERE key_sha256=$sha AND repo_full_name=$repo AND file_path=$path;
            """;
        update.Parameters.AddWithValue("$last", now);
        update.Parameters.AddWithValue("$model", (object?)f.ModelHint ?? DBNull.Value);
        update.Parameters.AddWithValue("$csha", (object?)f.CommitSha ?? DBNull.Value);
        update.Parameters.AddWithValue("$branch", (object?)f.DefaultBranch ?? DBNull.Value);
        update.Parameters.AddWithValue("$sha", f.KeySha256);
        update.Parameters.AddWithValue("$repo", f.RepoFullName);
        update.Parameters.AddWithValue("$path", f.FilePath);
        update.ExecuteNonQuery();
        return false;
    }

    public IReadOnlyList<Finding> AllFindings()
    {
        var list = new List<Finding>();
        using var cmd = _con.CreateCommand();
        cmd.CommandText = "SELECT * FROM findings ORDER BY first_seen_utc DESC";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new Finding(
                Provider: r.GetString(r.GetOrdinal("provider")),
                ExposureType: GetNullableString(r, "exposure_type") ?? "ApiKey",
                ModelHint: GetNullableString(r, "model_hint"),
                RepoFullName: r.GetString(r.GetOrdinal("repo_full_name")),
                RepoUrl: GetNullableString(r, "repo_url") ?? "",
                RepoHtmlUrl: GetNullableString(r, "repo_html_url") ?? "",
                AuthorLogin: GetNullableString(r, "author_login"),
                FilePath: r.GetString(r.GetOrdinal("file_path")),
                FileHtmlUrl: GetNullableString(r, "file_html_url") ?? "",
                CommitSha: GetNullableString(r, "commit_sha"),
                DefaultBranch: GetNullableString(r, "default_branch"),
                KeySha256: r.GetString(r.GetOrdinal("key_sha256")),
                KeyPrefix: GetNullableString(r, "key_prefix") ?? "",
                KeyLength: r.GetInt32(r.GetOrdinal("key_length")))
            {
                FirstSeenUtc = GetNullableString(r, "first_seen_utc"),
                LastSeenUtc = GetNullableString(r, "last_seen_utc"),
            });
        }
        return list;
    }

    public (int findings, int scannedFiles) Stats()
    {
        return (CountOf("findings"), CountOf("scanned_files"));
    }

    /// <summary>
    /// Watermark across all writeable timestamps so the Web UI's live
    /// poller can skip rebuilds when the DB hasn't advanced since the
    /// last refresh. Cheap O(1) — three indexed MAX() queries.
    /// </summary>
    public string? MaxLastSeenUtc()
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = """
            SELECT MAX(t) FROM (
              SELECT MAX(last_seen_utc) AS t FROM findings
              UNION ALL
              SELECT MAX(sent_at_utc)   AS t FROM notices
              UNION ALL
              SELECT MAX(checked_at_utc) AS t FROM remediation_checks
            )
            """;
        var v = cmd.ExecuteScalar();
        return v is string s ? s : null;
    }

    public sealed record ExposureTypeRow(string Name, string? Description, bool AutoInform);

    public IReadOnlyList<ExposureTypeRow> AllExposureTypes()
    {
        var list = new List<ExposureTypeRow>();
        using var cmd = _con.CreateCommand();
        cmd.CommandText = "SELECT name, description, auto_inform FROM exposure_types ORDER BY name";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new ExposureTypeRow(
                Name: r.GetString(0),
                Description: r.IsDBNull(1) ? null : r.GetString(1),
                AutoInform: r.GetInt32(2) != 0));
        }
        return list;
    }

    public bool GetAutoInform(string exposureType)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = "SELECT auto_inform FROM exposure_types WHERE name=$n";
        cmd.Parameters.AddWithValue("$n", exposureType);
        var v = cmd.ExecuteScalar();
        return v is long n ? n != 0 : false;
    }

    public void SetAutoInform(string exposureType, bool value)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = "UPDATE exposure_types SET auto_inform=$v WHERE name=$n";
        cmd.Parameters.AddWithValue("$v", value ? 1 : 0);
        cmd.Parameters.AddWithValue("$n", exposureType);
        cmd.ExecuteNonQuery();
    }

    public Notice? GetNotice(string keySha256, string repo, string path, string channel)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = """
            SELECT * FROM notices
             WHERE key_sha256=$sha AND repo_full_name=$repo
               AND file_path=$path AND channel=$ch
            """;
        cmd.Parameters.AddWithValue("$sha", keySha256);
        cmd.Parameters.AddWithValue("$repo", repo);
        cmd.Parameters.AddWithValue("$path", path);
        cmd.Parameters.AddWithValue("$ch", channel);
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadNotice(r) : null;
    }

    public IReadOnlyList<Notice> AllNotices()
    {
        var list = new List<Notice>();
        using var cmd = _con.CreateCommand();
        cmd.CommandText = "SELECT * FROM notices ORDER BY sent_at_utc DESC";
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(ReadNotice(r));
        return list;
    }

    /// <summary>
    /// Insert a notice. Caller is responsible for not double-sending —
    /// check GetNotice first. Throws if a row already exists for the
    /// (finding, channel) tuple.
    /// </summary>
    public void InsertNotice(Notice n)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = """
            INSERT INTO notices (
                key_sha256, repo_full_name, file_path, channel,
                issue_number, issue_html_url, sent_at_utc, status, error
            ) VALUES (
                $sha, $repo, $path, $ch,
                $num, $url, $sent, $status, $err
            );
            """;
        cmd.Parameters.AddWithValue("$sha", n.KeySha256);
        cmd.Parameters.AddWithValue("$repo", n.RepoFullName);
        cmd.Parameters.AddWithValue("$path", n.FilePath);
        cmd.Parameters.AddWithValue("$ch", n.Channel);
        cmd.Parameters.AddWithValue("$num", (object?)n.IssueNumber ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$url", (object?)n.IssueHtmlUrl ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$sent", n.SentAtUtc);
        cmd.Parameters.AddWithValue("$status", n.Status);
        cmd.Parameters.AddWithValue("$err", (object?)n.Error ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    public void DeleteNotice(string keySha256, string repo, string path, string channel)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = """
            DELETE FROM notices
             WHERE key_sha256=$sha AND repo_full_name=$repo
               AND file_path=$path AND channel=$ch
            """;
        cmd.Parameters.AddWithValue("$sha", keySha256);
        cmd.Parameters.AddWithValue("$repo", repo);
        cmd.Parameters.AddWithValue("$path", path);
        cmd.Parameters.AddWithValue("$ch", channel);
        cmd.ExecuteNonQuery();
    }

    public void InsertRemediationCheck(RemediationCheck c)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = """
            INSERT OR IGNORE INTO remediation_checks (
                key_sha256, repo_full_name, file_path,
                checked_at_utc, status, commit_sha
            ) VALUES ($sha, $repo, $path, $when, $status, $csha);
            """;
        cmd.Parameters.AddWithValue("$sha", c.KeySha256);
        cmd.Parameters.AddWithValue("$repo", c.RepoFullName);
        cmd.Parameters.AddWithValue("$path", c.FilePath);
        cmd.Parameters.AddWithValue("$when", c.CheckedAtUtc);
        cmd.Parameters.AddWithValue("$status", c.Status);
        cmd.Parameters.AddWithValue("$csha", (object?)c.CommitSha ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// How many remediation checks ('check-backs') have been recorded per
    /// finding. Drives the 'Checks' column in the Findings UI and the
    /// time-to-remediate distribution chart.
    /// </summary>
    public Dictionary<(string KeySha256, string Repo, string Path), int>
        RemediationCheckCounts()
    {
        var result = new Dictionary<(string, string, string), int>();
        using var cmd = _con.CreateCommand();
        cmd.CommandText = """
            SELECT key_sha256, repo_full_name, file_path, COUNT(*) AS n
              FROM remediation_checks
             GROUP BY key_sha256, repo_full_name, file_path
            """;
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            result[(
                r.GetString(0), r.GetString(1), r.GetString(2)
            )] = r.GetInt32(3);
        }
        return result;
    }

    public IReadOnlyList<RemediationCheck> AllRemediationChecks()
    {
        var list = new List<RemediationCheck>();
        using var cmd = _con.CreateCommand();
        cmd.CommandText =
            "SELECT * FROM remediation_checks ORDER BY checked_at_utc ASC";
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(ReadRemediation(r));
        return list;
    }

    /// <summary>
    /// Latest remediation check per finding, joined back to findings.
    /// Used by the recheck pass to skip findings already in a terminal
    /// state (removed | repo_gone) and by the Web UI to display status.
    /// </summary>
    public Dictionary<(string KeySha256, string Repo, string Path), RemediationCheck>
        LatestRemediationChecks()
    {
        var result = new Dictionary<(string, string, string), RemediationCheck>();
        using var cmd = _con.CreateCommand();
        cmd.CommandText = """
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
            """;
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var c = ReadRemediation(r);
            result[(c.KeySha256, c.RepoFullName, c.FilePath)] = c;
        }
        return result;
    }

    private int CountOf(string table)
    {
        using var cmd = _con.CreateCommand();
        cmd.CommandText = $"SELECT COUNT(*) FROM {table}";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    /// <summary>
    /// One-shot migrator. If a sibling findings.json exists and the DB has
    /// no records yet, import it. Returns the count newly inserted.
    /// </summary>
    public int MaybeImportLegacy(FileInfo dbPath)
    {
        var legacy = new FileInfo(Path.ChangeExtension(dbPath.FullName, ".json"));
        if (!legacy.Exists) return 0;
        if (CountOf("findings") > 0) return 0;

        List<System.Text.Json.JsonElement>? records;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(legacy.FullName));
            records = doc.RootElement.EnumerateArray().Select(e => e.Clone()).ToList();
        }
        catch (System.Text.Json.JsonException)
        {
            return 0;
        }

        var n = 0;
        using var tx = _con.BeginTransaction();
        foreach (var r in records)
        {
            var sha = GetJsonString(r, "key_sha256");
            var repo = GetJsonString(r, "repo_full_name");
            if (string.IsNullOrEmpty(sha) || string.IsNullOrEmpty(repo)) continue;
            var f = new Finding(
                Provider: GetJsonString(r, "provider") ?? "",
                ExposureType: GetJsonString(r, "exposure_type") ?? "ApiKey",
                ModelHint: GetJsonString(r, "model_hint"),
                RepoFullName: repo!,
                RepoUrl: GetJsonString(r, "repo_url") ?? "",
                RepoHtmlUrl: GetJsonString(r, "repo_html_url") ?? "",
                AuthorLogin: GetJsonString(r, "author_login"),
                FilePath: GetJsonString(r, "file_path") ?? "",
                FileHtmlUrl: GetJsonString(r, "file_html_url") ?? "",
                CommitSha: GetJsonString(r, "commit_sha"),
                DefaultBranch: GetJsonString(r, "default_branch"),
                KeySha256: sha!,
                KeyPrefix: GetJsonString(r, "key_prefix") ?? "",
                KeyLength: GetJsonInt(r, "key_length"));
            if (UpsertFinding(f, firstSeenOverride: GetJsonString(r, "detected_at_utc"))) n++;
            MarkScanned(f.RepoFullName, f.FilePath, f.CommitSha);
        }
        tx.Commit();
        return n;
    }

    private static string? GetNullableString(SqliteDataReader r, string col)
    {
        var i = r.GetOrdinal(col);
        return r.IsDBNull(i) ? null : r.GetString(i);
    }

    private static int? GetNullableInt(SqliteDataReader r, string col)
    {
        var i = r.GetOrdinal(col);
        return r.IsDBNull(i) ? null : r.GetInt32(i);
    }

    private static Notice ReadNotice(SqliteDataReader r) => new(
        KeySha256: r.GetString(r.GetOrdinal("key_sha256")),
        RepoFullName: r.GetString(r.GetOrdinal("repo_full_name")),
        FilePath: r.GetString(r.GetOrdinal("file_path")),
        Channel: r.GetString(r.GetOrdinal("channel")),
        IssueNumber: GetNullableInt(r, "issue_number"),
        IssueHtmlUrl: GetNullableString(r, "issue_html_url"),
        SentAtUtc: r.GetString(r.GetOrdinal("sent_at_utc")),
        Status: r.GetString(r.GetOrdinal("status")),
        Error: GetNullableString(r, "error"));

    private static RemediationCheck ReadRemediation(SqliteDataReader r) => new(
        KeySha256: r.GetString(r.GetOrdinal("key_sha256")),
        RepoFullName: r.GetString(r.GetOrdinal("repo_full_name")),
        FilePath: r.GetString(r.GetOrdinal("file_path")),
        CheckedAtUtc: r.GetString(r.GetOrdinal("checked_at_utc")),
        Status: r.GetString(r.GetOrdinal("status")),
        CommitSha: GetNullableString(r, "commit_sha"));

    private static string? GetJsonString(System.Text.Json.JsonElement el, string name)
    {
        if (!el.TryGetProperty(name, out var v)) return null;
        return v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() : null;
    }

    private static int GetJsonInt(System.Text.Json.JsonElement el, string name)
    {
        if (!el.TryGetProperty(name, out var v)) return 0;
        return v.ValueKind == System.Text.Json.JsonValueKind.Number && v.TryGetInt32(out var i)
            ? i : 0;
    }

    public void Dispose()
    {
        _con.Dispose();
    }
}
