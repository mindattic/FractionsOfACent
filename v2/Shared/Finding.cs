namespace FractionsOfACent;

/// <summary>
/// One metadata record per detected leak. No raw key is stored — only a
/// SHA-256 hash and a non-sensitive 16-char prefix (scheme marker only).
/// Timestamps are owned by the DB (first_seen_utc / last_seen_utc).
/// </summary>
public sealed record Finding(
    string Provider,
    string ExposureType,
    string? ModelHint,
    string RepoFullName,
    string RepoUrl,
    string RepoHtmlUrl,
    string? AuthorLogin,
    string FilePath,
    string FileHtmlUrl,
    string? CommitSha,
    string? DefaultBranch,
    string KeySha256,
    string KeyPrefix,
    int KeyLength)
{
    /// <summary>
    /// Populated only when materializing rows out of the DB. Newly-detected
    /// findings inside Scraper leave this null and let the DB stamp it.
    /// </summary>
    public string? FirstSeenUtc { get; init; }
    public string? LastSeenUtc { get; init; }
}
