namespace FractionsOfACent;

/// <summary>
/// Configuration for the notice template. Lives in Web's appsettings.json,
/// or — when called from the CLI — falls back to NoticeConfig.Default.
/// Tokens replaced in title/body:
///   {provider} {repo} {file_path} {file_html_url}
///   {key_sha_short} {key_prefix} {detected_at}
/// </summary>
public sealed record NoticeConfig(
    string Channel,
    string Title,
    string Body)
{
    public static NoticeConfig Default { get; } = new(
        Channel: "github_issue",
        Title: "Exposed credential ({exposure_type}) detected in this repository",
        Body: """
            Hi {author_at},

            A public-service research scanner has flagged what looks like a leaked credential (`{exposure_type}` / **{provider}**) committed to this public repository.

            - File: {file_html_url}
            - Credential fingerprint (SHA-256, first 16 chars): `{key_sha_short}`
            - Scheme prefix (marker only, not the secret): `{key_prefix}`
            - First detected: {detected_at}

            **What to do**

            1. Treat this credential as compromised and revoke / rotate it at the provider's console immediately.
            2. Remove it from current files and from git history (e.g. `git filter-repo`, `git filter-branch`, or BFG). A force-push alone is not sufficient — the commit may already be cached, forked, or scraped.
            3. Rotate any other secrets that may have been committed alongside this one.
            4. Enable [GitHub Push Protection](https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations) so future leaks are blocked at push time.

            **About this notice**

            This is a courtesy notification from an automated public-service credential-disclosure project. We do **not** retain the credential — only its SHA-256 hash and a short scheme prefix — and we do **not** validate it against the provider's API. The provider's secret-scanning partner program will also surface this leak through their own channel.

            Once you've rotated and cleaned, feel free to close this issue. Thanks for keeping the ecosystem safer.
            """);
}

public sealed record NoticeSendResult(
    bool Ok,
    int? IssueNumber,
    string? IssueHtmlUrl,
    string? Error,
    bool Skipped);

/// <summary>
/// Opens a GitHub issue on the leaker's repo and records a notices row.
/// Idempotent on (finding, channel): if a notice already exists, returns
/// Skipped=true without re-opening. Both the CLI scraper and the Blazor
/// 'Retry' button call this same path.
/// </summary>
public sealed class NoticeService
{
    private readonly Db _db;
    private readonly GitHubClient _client;
    private readonly NoticeConfig _config;

    public NoticeService(Db db, GitHubClient client, NoticeConfig? config = null)
    {
        _db = db;
        _client = client;
        _config = config ?? NoticeConfig.Default;
    }

    public async Task<NoticeSendResult> SendAsync(
        Finding finding, CancellationToken ct = default)
    {
        var existing = _db.GetNotice(
            finding.KeySha256, finding.RepoFullName, finding.FilePath, _config.Channel);
        if (existing is { Status: "sent" })
        {
            return new NoticeSendResult(
                true, existing.IssueNumber, existing.IssueHtmlUrl, null, Skipped: true);
        }

        var title = Render(_config.Title, finding);
        var body = Render(_config.Body, finding);
        var result = await _client.OpenIssueAsync(
            finding.RepoFullName, title, body, ct);

        var notice = new Notice(
            KeySha256: finding.KeySha256,
            RepoFullName: finding.RepoFullName,
            FilePath: finding.FilePath,
            Channel: _config.Channel,
            IssueNumber: result.Number,
            IssueHtmlUrl: result.HtmlUrl,
            SentAtUtc: DateTime.UtcNow.ToString("O"),
            Status: result.Ok ? "sent" : "failed",
            Error: result.Error);

        // If we have an existing 'failed' row, replace it; else insert.
        if (existing is not null)
        {
            _db.DeleteNotice(
                finding.KeySha256, finding.RepoFullName, finding.FilePath, _config.Channel);
        }
        _db.InsertNotice(notice);

        return new NoticeSendResult(
            result.Ok, result.Number, result.HtmlUrl, result.Error, Skipped: false);
    }

    private static string Render(string template, Finding f) => template
        .Replace("{provider}", f.Provider)
        .Replace("{exposure_type}", f.ExposureType)
        .Replace("{repo}", f.RepoFullName)
        .Replace("{author_at}",
            string.IsNullOrEmpty(f.AuthorLogin) ? "there" : "@" + f.AuthorLogin)
        .Replace("{author_login}", f.AuthorLogin ?? "")
        .Replace("{file_path}", f.FilePath)
        .Replace("{file_html_url}", f.FileHtmlUrl)
        .Replace("{key_sha_short}",
            f.KeySha256.Length >= 16 ? f.KeySha256[..16] : f.KeySha256)
        .Replace("{key_prefix}", f.KeyPrefix)
        .Replace("{detected_at}", f.FirstSeenUtc ?? "(unknown)");
}
