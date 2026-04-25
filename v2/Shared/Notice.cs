namespace FractionsOfACent;

/// <summary>
/// One takedown notice we sent to the leaker. The (KeySha256, RepoFullName,
/// FilePath, Channel) tuple is the primary key — re-sending on the same
/// channel is a no-op (caller checks first), so a 'sent' row blocks dupes.
/// </summary>
public sealed record Notice(
    string KeySha256,
    string RepoFullName,
    string FilePath,
    string Channel,
    int? IssueNumber,
    string? IssueHtmlUrl,
    string SentAtUtc,
    string Status,
    string? Error);

/// <summary>
/// One remediation check. Append-only — the latest row per finding is the
/// current status; the series is the time-to-revocation signal.
/// Status: present | removed | file_gone | repo_gone | fetch_failed.
/// </summary>
public sealed record RemediationCheck(
    string KeySha256,
    string RepoFullName,
    string FilePath,
    string CheckedAtUtc,
    string Status,
    string? CommitSha);
