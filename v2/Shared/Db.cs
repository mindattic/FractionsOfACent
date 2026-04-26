using Microsoft.EntityFrameworkCore;

namespace FractionsOfACent;

/// <summary>
/// Persistence facade. Backed by EF Core against SQL Server LocalDB.
/// The CLI scraper (`fractions`) is the writer and runs continuously;
/// the Blazor app reads from the same database. Method names mirror the
/// previous SQLite implementation so call sites in Scraper / NoticeService
/// / Blazor pages did not need to change.
///
/// EF DbContext is not thread-safe, so each method opens and disposes its
/// own context via IDbContextFactory. Reads use AsNoTracking() — no
/// long-lived change tracking needed for what is effectively a snapshot UI.
/// No raw API keys are persisted (only SHA-256 + 16-char prefix).
/// </summary>
public sealed class Db : IDisposable
{
    private readonly IDbContextFactory<FractionsContext> _factory;
    private readonly InlineFactory? _ownedFactory;

    public Db(IDbContextFactory<FractionsContext> factory)
    {
        _factory = factory;
    }

    private Db(InlineFactory owned)
    {
        _factory = owned;
        _ownedFactory = owned;
    }

    /// <summary>
    /// Convenience for the CLI: build a factory from a connection string,
    /// ensure the schema exists (Migrate), seed exposure types. Disposes
    /// the owned factory when this Db is disposed.
    /// </summary>
    public static Db CreateForCli(string connectionString)
    {
        var owned = new InlineFactory(connectionString);
        using (var ctx = owned.CreateDbContext())
        {
            ctx.Database.Migrate();
        }
        var db = new Db(owned);
        db.SeedExposureTypes();
        return db;
    }

    /// <summary>
    /// Used by Web's startup code on its DI-registered factory.
    /// </summary>
    public static void EnsureCreatedAndSeeded(IDbContextFactory<FractionsContext> factory)
    {
        using (var ctx = factory.CreateDbContext())
        {
            ctx.Database.Migrate();
        }
        new Db(factory).SeedExposureTypes();
    }

    private void SeedExposureTypes()
    {
        using var ctx = _factory.CreateDbContext();
        var existing = ctx.ExposureTypes.ToDictionary(e => e.Name);
        foreach (var (name, description) in ExposureTypes.All)
        {
            if (existing.TryGetValue(name, out var row))
            {
                if (row.Description != description)
                {
                    row.Description = description;
                }
            }
            else
            {
                ctx.ExposureTypes.Add(new ExposureTypeEntity
                {
                    Name = name,
                    Description = description,
                    AutoInform = false,
                });
            }
        }
        if (!ctx.ScannerControls.Any(c => c.Id == 1))
        {
            ctx.ScannerControls.Add(new ScannerControlEntity
            {
                Id = 1,
                RequestedState = "running",
                RequestedAtUtc = DateTime.UtcNow,
            });
        }
        ctx.SaveChanges();
    }

    public sealed record ScannerControlSnapshot(
        string RequestedState,
        DateTime RequestedAtUtc,
        DateTime? LastHeartbeatUtc,
        string? CurrentLabel);

    public ScannerControlSnapshot GetScannerControl()
    {
        using var ctx = _factory.CreateDbContext();
        var row = ctx.ScannerControls.AsNoTracking().FirstOrDefault(c => c.Id == 1);
        return row is null
            ? new ScannerControlSnapshot("running", DateTime.UtcNow, null, null)
            : new ScannerControlSnapshot(
                row.RequestedState, row.RequestedAtUtc,
                row.LastHeartbeatUtc, row.CurrentLabel);
    }

    public void SetScannerRequestedState(string state)
    {
        if (state is not ("running" or "paused"))
            throw new ArgumentException($"invalid state: {state}", nameof(state));
        using var ctx = _factory.CreateDbContext();
        var row = ctx.ScannerControls.FirstOrDefault(c => c.Id == 1);
        if (row is null)
        {
            ctx.ScannerControls.Add(new ScannerControlEntity
            {
                Id = 1,
                RequestedState = state,
                RequestedAtUtc = DateTime.UtcNow,
            });
        }
        else
        {
            row.RequestedState = state;
            row.RequestedAtUtc = DateTime.UtcNow;
        }
        ctx.SaveChanges();
    }

    public void WriteScannerHeartbeat(string label)
    {
        using var ctx = _factory.CreateDbContext();
        var row = ctx.ScannerControls.FirstOrDefault(c => c.Id == 1);
        if (row is null) return;
        row.LastHeartbeatUtc = DateTime.UtcNow;
        row.CurrentLabel = label;
        ctx.SaveChanges();
    }

    public bool IsScanned(string repo, string path)
    {
        using var ctx = _factory.CreateDbContext();
        return ctx.ScannedFiles.AsNoTracking()
            .Any(s => s.RepoFullName == repo && s.FilePath == path);
    }

    /// <summary>
    /// Atomically claim a (repo, path). Returns true iff this caller won
    /// the race to insert; false if another writer already had the row.
    /// Concurrency safe via PK uniqueness — second insert raises
    /// DbUpdateException, which we swallow.
    /// </summary>
    public bool ClaimScan(string repo, string path)
    {
        using var ctx = _factory.CreateDbContext();
        ctx.ScannedFiles.Add(new ScannedFileEntity
        {
            RepoFullName = repo,
            FilePath = path,
            CommitSha = null,
            ScannedAtUtc = DateTime.UtcNow,
        });
        try
        {
            ctx.SaveChanges();
            return true;
        }
        catch (DbUpdateException)
        {
            return false;
        }
    }

    public void RecordCommitForScan(string repo, string path, string? commitSha)
    {
        using var ctx = _factory.CreateDbContext();
        var row = ctx.ScannedFiles.FirstOrDefault(
            s => s.RepoFullName == repo && s.FilePath == path);
        if (row is null) return;
        row.CommitSha = commitSha;
        row.ScannedAtUtc = DateTime.UtcNow;
        ctx.SaveChanges();
    }

    public void MarkScanned(string repo, string path, string? commitSha)
    {
        using var ctx = _factory.CreateDbContext();
        var row = ctx.ScannedFiles.FirstOrDefault(
            s => s.RepoFullName == repo && s.FilePath == path);
        if (row is null)
        {
            ctx.ScannedFiles.Add(new ScannedFileEntity
            {
                RepoFullName = repo,
                FilePath = path,
                CommitSha = commitSha,
                ScannedAtUtc = DateTime.UtcNow,
            });
        }
        else
        {
            row.CommitSha = commitSha;
            row.ScannedAtUtc = DateTime.UtcNow;
        }
        ctx.SaveChanges();
    }

    /// <summary>
    /// Returns true iff the row was newly inserted. On conflict,
    /// LastSeenUtc is bumped and any newly-known model_hint /
    /// commit_sha / default_branch is backfilled.
    /// </summary>
    public bool UpsertFinding(Finding f, string? firstSeenOverride = null)
    {
        using var ctx = _factory.CreateDbContext();
        var now = DateTime.UtcNow;
        var firstSeen = ParseUtc(firstSeenOverride) ?? now;

        var existing = ctx.Findings.FirstOrDefault(
            x => x.KeySha256 == f.KeySha256
              && x.RepoFullName == f.RepoFullName
              && x.FilePath == f.FilePath);

        if (existing is null)
        {
            ctx.Findings.Add(new FindingEntity
            {
                KeySha256 = f.KeySha256,
                RepoFullName = f.RepoFullName,
                FilePath = f.FilePath,
                Provider = f.Provider,
                ExposureType = f.ExposureType,
                ModelHint = f.ModelHint,
                RepoUrl = f.RepoUrl,
                RepoHtmlUrl = f.RepoHtmlUrl,
                AuthorLogin = f.AuthorLogin,
                FileHtmlUrl = f.FileHtmlUrl,
                CommitSha = f.CommitSha,
                DefaultBranch = f.DefaultBranch,
                KeyPrefix = f.KeyPrefix,
                KeyLength = f.KeyLength,
                FirstSeenUtc = firstSeen,
                LastSeenUtc = now,
            });
            try
            {
                ctx.SaveChanges();
                return true;
            }
            catch (DbUpdateException)
            {
                // Lost the insert race — fall through to the update path.
                ctx.ChangeTracker.Clear();
                existing = ctx.Findings.First(
                    x => x.KeySha256 == f.KeySha256
                      && x.RepoFullName == f.RepoFullName
                      && x.FilePath == f.FilePath);
            }
        }

        existing!.LastSeenUtc = now;
        existing.ModelHint ??= f.ModelHint;
        if (!string.IsNullOrEmpty(f.CommitSha)) existing.CommitSha = f.CommitSha;
        if (!string.IsNullOrEmpty(f.DefaultBranch)) existing.DefaultBranch = f.DefaultBranch;
        ctx.SaveChanges();
        return false;
    }

    public IReadOnlyList<Finding> AllFindings()
    {
        using var ctx = _factory.CreateDbContext();
        return ctx.Findings.AsNoTracking()
            .OrderByDescending(f => f.FirstSeenUtc)
            .ToList()
            .Select(ToRecord)
            .ToList();
    }

    public (int findings, int scannedFiles) Stats()
    {
        using var ctx = _factory.CreateDbContext();
        return (ctx.Findings.Count(), ctx.ScannedFiles.Count());
    }

    /// <summary>
    /// Watermark across all writeable timestamps so the Web UI's live
    /// poller can skip rebuilds when the DB hasn't advanced.
    /// </summary>
    public string? MaxLastSeenUtc()
    {
        using var ctx = _factory.CreateDbContext();
        var maxFinding = ctx.Findings.AsNoTracking().Max(f => (DateTime?)f.LastSeenUtc);
        var maxNotice = ctx.Notices.AsNoTracking().Max(n => (DateTime?)n.SentAtUtc);
        var maxCheck = ctx.RemediationChecks.AsNoTracking().Max(c => (DateTime?)c.CheckedAtUtc);
        DateTime? best = null;
        foreach (var v in new[] { maxFinding, maxNotice, maxCheck })
        {
            if (v.HasValue && (!best.HasValue || v.Value > best.Value)) best = v;
        }
        return best?.ToString("O");
    }

    public sealed record ExposureTypeRow(string Name, string? Description, bool AutoInform);

    public IReadOnlyList<ExposureTypeRow> AllExposureTypes()
    {
        using var ctx = _factory.CreateDbContext();
        return ctx.ExposureTypes.AsNoTracking()
            .OrderBy(e => e.Name)
            .Select(e => new ExposureTypeRow(e.Name, e.Description, e.AutoInform))
            .ToList();
    }

    public bool GetAutoInform(string exposureType)
    {
        using var ctx = _factory.CreateDbContext();
        return ctx.ExposureTypes.AsNoTracking()
            .Where(e => e.Name == exposureType)
            .Select(e => (bool?)e.AutoInform)
            .FirstOrDefault() ?? false;
    }

    public void SetAutoInform(string exposureType, bool value)
    {
        using var ctx = _factory.CreateDbContext();
        var row = ctx.ExposureTypes.FirstOrDefault(e => e.Name == exposureType);
        if (row is null) return;
        row.AutoInform = value;
        ctx.SaveChanges();
    }

    public Notice? GetNotice(string keySha256, string repo, string path, string channel)
    {
        using var ctx = _factory.CreateDbContext();
        var n = ctx.Notices.AsNoTracking().FirstOrDefault(x =>
            x.KeySha256 == keySha256 && x.RepoFullName == repo
            && x.FilePath == path && x.Channel == channel);
        return n is null ? null : ToRecord(n);
    }

    public IReadOnlyList<Notice> AllNotices()
    {
        using var ctx = _factory.CreateDbContext();
        return ctx.Notices.AsNoTracking()
            .OrderByDescending(n => n.SentAtUtc)
            .ToList()
            .Select(ToRecord)
            .ToList();
    }

    public void InsertNotice(Notice n)
    {
        using var ctx = _factory.CreateDbContext();
        ctx.Notices.Add(new NoticeEntity
        {
            KeySha256 = n.KeySha256,
            RepoFullName = n.RepoFullName,
            FilePath = n.FilePath,
            Channel = n.Channel,
            IssueNumber = n.IssueNumber,
            IssueHtmlUrl = n.IssueHtmlUrl,
            SentAtUtc = ParseUtc(n.SentAtUtc) ?? DateTime.UtcNow,
            Status = n.Status,
            Error = n.Error,
        });
        ctx.SaveChanges();
    }

    public void DeleteNotice(string keySha256, string repo, string path, string channel)
    {
        using var ctx = _factory.CreateDbContext();
        var row = ctx.Notices.FirstOrDefault(x =>
            x.KeySha256 == keySha256 && x.RepoFullName == repo
            && x.FilePath == path && x.Channel == channel);
        if (row is null) return;
        ctx.Notices.Remove(row);
        ctx.SaveChanges();
    }

    public void InsertRemediationCheck(RemediationCheck c)
    {
        using var ctx = _factory.CreateDbContext();
        var checkedAt = ParseUtc(c.CheckedAtUtc) ?? DateTime.UtcNow;
        var dup = ctx.RemediationChecks.Any(x =>
            x.KeySha256 == c.KeySha256 && x.RepoFullName == c.RepoFullName
            && x.FilePath == c.FilePath && x.CheckedAtUtc == checkedAt);
        if (dup) return;
        ctx.RemediationChecks.Add(new RemediationCheckEntity
        {
            KeySha256 = c.KeySha256,
            RepoFullName = c.RepoFullName,
            FilePath = c.FilePath,
            CheckedAtUtc = checkedAt,
            Status = c.Status,
            CommitSha = c.CommitSha,
        });
        ctx.SaveChanges();
    }

    public Dictionary<(string KeySha256, string Repo, string Path), int>
        RemediationCheckCounts()
    {
        using var ctx = _factory.CreateDbContext();
        return ctx.RemediationChecks.AsNoTracking()
            .GroupBy(c => new { c.KeySha256, c.RepoFullName, c.FilePath })
            .Select(g => new
            {
                g.Key.KeySha256,
                g.Key.RepoFullName,
                g.Key.FilePath,
                Count = g.Count(),
            })
            .ToList()
            .ToDictionary(
                r => (r.KeySha256, r.RepoFullName, r.FilePath),
                r => r.Count);
    }

    public IReadOnlyList<RemediationCheck> AllRemediationChecks()
    {
        using var ctx = _factory.CreateDbContext();
        return ctx.RemediationChecks.AsNoTracking()
            .OrderBy(c => c.CheckedAtUtc)
            .ToList()
            .Select(ToRecord)
            .ToList();
    }

    public Dictionary<(string KeySha256, string Repo, string Path), RemediationCheck>
        LatestRemediationChecks()
    {
        using var ctx = _factory.CreateDbContext();
        // Per-finding latest check via window-style group-aggregate.
        var latest = ctx.RemediationChecks.AsNoTracking()
            .GroupBy(c => new { c.KeySha256, c.RepoFullName, c.FilePath })
            .Select(g => new
            {
                g.Key.KeySha256,
                g.Key.RepoFullName,
                g.Key.FilePath,
                Latest = g.Max(c => c.CheckedAtUtc),
            })
            .ToList();

        var result = new Dictionary<(string, string, string), RemediationCheck>(latest.Count);
        foreach (var l in latest)
        {
            var row = ctx.RemediationChecks.AsNoTracking().FirstOrDefault(c =>
                c.KeySha256 == l.KeySha256
                && c.RepoFullName == l.RepoFullName
                && c.FilePath == l.FilePath
                && c.CheckedAtUtc == l.Latest);
            if (row is not null)
            {
                result[(l.KeySha256, l.RepoFullName, l.FilePath)] = ToRecord(row);
            }
        }
        return result;
    }

    private static DateTime? ParseUtc(string? iso)
    {
        if (string.IsNullOrEmpty(iso)) return null;
        return DateTime.TryParse(
            iso, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal
                | System.Globalization.DateTimeStyles.AdjustToUniversal,
            out var dt) ? dt : null;
    }

    private static string Iso(DateTime dt) =>
        DateTime.SpecifyKind(dt, DateTimeKind.Utc).ToString("O");

    private static Finding ToRecord(FindingEntity e) => new(
        Provider: e.Provider,
        ExposureType: e.ExposureType,
        ModelHint: e.ModelHint,
        RepoFullName: e.RepoFullName,
        RepoUrl: e.RepoUrl ?? "",
        RepoHtmlUrl: e.RepoHtmlUrl ?? "",
        AuthorLogin: e.AuthorLogin,
        FilePath: e.FilePath,
        FileHtmlUrl: e.FileHtmlUrl ?? "",
        CommitSha: e.CommitSha,
        DefaultBranch: e.DefaultBranch,
        KeySha256: e.KeySha256,
        KeyPrefix: e.KeyPrefix ?? "",
        KeyLength: e.KeyLength)
    {
        FirstSeenUtc = Iso(e.FirstSeenUtc),
        LastSeenUtc = Iso(e.LastSeenUtc),
    };

    private static Notice ToRecord(NoticeEntity e) => new(
        KeySha256: e.KeySha256,
        RepoFullName: e.RepoFullName,
        FilePath: e.FilePath,
        Channel: e.Channel,
        IssueNumber: e.IssueNumber,
        IssueHtmlUrl: e.IssueHtmlUrl,
        SentAtUtc: Iso(e.SentAtUtc),
        Status: e.Status,
        Error: e.Error);

    private static RemediationCheck ToRecord(RemediationCheckEntity e) => new(
        KeySha256: e.KeySha256,
        RepoFullName: e.RepoFullName,
        FilePath: e.FilePath,
        CheckedAtUtc: Iso(e.CheckedAtUtc),
        Status: e.Status,
        CommitSha: e.CommitSha);

    public void Dispose() => _ownedFactory?.Dispose();

    private sealed class InlineFactory : IDbContextFactory<FractionsContext>, IDisposable
    {
        private readonly DbContextOptions<FractionsContext> _opts;
        public InlineFactory(string cs)
        {
            _opts = new DbContextOptionsBuilder<FractionsContext>()
                .UseSqlServer(cs).Options;
        }
        public FractionsContext CreateDbContext() => new(_opts);
        public void Dispose() { }
    }
}
