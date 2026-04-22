namespace FractionsOfAPenny;

/// <summary>
/// One metadata record per detected leak. No raw key is stored — only a
/// SHA-256 hash and a non-sensitive 16-char prefix (scheme marker only).
/// </summary>
public sealed record Finding(
    string Provider,
    string? ModelHint,
    string RepoFullName,
    string RepoUrl,
    string RepoHtmlUrl,
    string? AuthorLogin,
    string FilePath,
    string FileHtmlUrl,
    string? CommitSha,
    string? DefaultBranch,
    string DetectedAtUtc,
    string KeySha256,
    string KeyPrefix,
    int KeyLength);
