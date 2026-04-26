namespace FractionsOfACent;

/// <summary>
/// EF entity. The public-facing record (Finding) is preserved as a
/// transport DTO so callers don't churn; Db converts at the boundary.
/// Composite key (KeySha256, RepoFullName, FilePath) is configured in
/// FractionsContext via Fluent API.
/// </summary>
public class FindingEntity
{
    public string KeySha256 { get; set; } = "";
    public string RepoFullName { get; set; } = "";
    public string FilePath { get; set; } = "";

    public string Provider { get; set; } = "";
    public string ExposureType { get; set; } = "ApiKey";
    public string? ModelHint { get; set; }
    public string? RepoUrl { get; set; }
    public string? RepoHtmlUrl { get; set; }
    public string? AuthorLogin { get; set; }
    public string? FileHtmlUrl { get; set; }
    public string? CommitSha { get; set; }
    public string? DefaultBranch { get; set; }
    public string? KeyPrefix { get; set; }
    public int KeyLength { get; set; }
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }

    public ExposureTypeEntity? ExposureTypeNav { get; set; }
}

public class ScannedFileEntity
{
    public string RepoFullName { get; set; } = "";
    public string FilePath { get; set; } = "";
    public string? CommitSha { get; set; }
    public DateTime ScannedAtUtc { get; set; }
}

public class NoticeEntity
{
    public string KeySha256 { get; set; } = "";
    public string RepoFullName { get; set; } = "";
    public string FilePath { get; set; } = "";
    public string Channel { get; set; } = "";

    public int? IssueNumber { get; set; }
    public string? IssueHtmlUrl { get; set; }
    public DateTime SentAtUtc { get; set; }
    public string Status { get; set; } = "";
    public string? Error { get; set; }
}

public class RemediationCheckEntity
{
    public string KeySha256 { get; set; } = "";
    public string RepoFullName { get; set; } = "";
    public string FilePath { get; set; } = "";
    public DateTime CheckedAtUtc { get; set; }

    public string Status { get; set; } = "";
    public string? CommitSha { get; set; }
}

public class ExposureTypeEntity
{
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public bool AutoInform { get; set; }
}

/// <summary>
/// Single-row cross-process control surface. The Blazor UI writes
/// RequestedState; the CLI scraper polls it at safe checkpoints and idles
/// when 'paused'. CLI also writes LastHeartbeatUtc + CurrentLabel each
/// iteration so the UI can show liveness.
/// </summary>
public class ScannerControlEntity
{
    public int Id { get; set; }
    public string RequestedState { get; set; } = "running";
    public DateTime RequestedAtUtc { get; set; }
    public DateTime? LastHeartbeatUtc { get; set; }
    public string? CurrentLabel { get; set; }
}
