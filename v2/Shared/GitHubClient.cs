using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FractionsOfACent;

public sealed class GitHubClient : IDisposable
{
    private const string ApiBase = "https://api.github.com";
    private const string UserAgent = "fractions-of-a-cent-research/0.1 (+academic study, metadata-only)";

    private readonly HttpClient _http;

    public GitHubClient(string token)
    {
        _http = new HttpClient { BaseAddress = new Uri(ApiBase) };
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
        _http.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        _http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        _http.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
        _http.Timeout = TimeSpan.FromSeconds(30);
    }

    public async IAsyncEnumerable<CodeSearchItem> SearchCodeAsync(
        string needle,
        int perPage = 30,
        int maxPages = 10,
        [System.Runtime.CompilerServices.EnumeratorCancellation]
        CancellationToken ct = default)
    {
        for (var page = 1; page <= maxPages; page++)
        {
            var url = $"/search/code?q={Uri.EscapeDataString(needle + " in:file")}&per_page={perPage}&page={page}";
            using var resp = await _http.GetAsync(url, ct);
            if (resp.StatusCode == HttpStatusCode.Forbidden)
            {
                await HandleRateLimitAsync(resp, ct);
                page--;
                continue;
            }
            if (resp.StatusCode == HttpStatusCode.UnprocessableEntity)
            {
                // "Only the first 1000 search results are available"
                yield break;
            }
            resp.EnsureSuccessStatusCode();

            var payload = await resp.Content.ReadFromJsonAsync<CodeSearchResponse>(
                cancellationToken: ct);
            var items = payload?.Items ?? [];
            if (items.Length == 0) yield break;
            foreach (var item in items) yield return item;

            // Courtesy delay between pages — Code Search is strict.
            await Task.Delay(TimeSpan.FromSeconds(2), ct);
        }
    }

    public async Task<FileContentResult> FetchFileAsync(
        CodeSearchItem item, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync(item.Url, ct);
        if (resp.StatusCode == HttpStatusCode.Forbidden)
        {
            await HandleRateLimitAsync(resp, ct);
            return new FileContentResult("", null);
        }
        if (!resp.IsSuccessStatusCode)
        {
            return new FileContentResult("", null);
        }

        var payload = await resp.Content.ReadFromJsonAsync<ContentsResponse>(
            cancellationToken: ct);
        if (payload is null) return new FileContentResult("", null);
        return ToResult(payload);
    }

    /// <summary>
    /// Re-fetch a known (repo, path) for remediation rechecks. Distinguishes
    /// 'file_gone' (404 on the file) from 'repo_gone' (404 on the repo
    /// itself, or 451 for DMCA takedowns) so the caller can record the
    /// right remediation status.
    /// </summary>
    public async Task<RefetchResult> RefetchAsync(
        string repoFullName, string path, CancellationToken ct = default)
    {
        // Path components must be URL-escaped individually so '/' separators survive.
        var escapedPath = string.Join('/',
            path.Split('/').Select(Uri.EscapeDataString));
        var url = $"/repos/{repoFullName}/contents/{escapedPath}";
        using var resp = await _http.GetAsync(url, ct);
        if (resp.StatusCode == HttpStatusCode.Forbidden)
        {
            await HandleRateLimitAsync(resp, ct);
            return new RefetchResult(RefetchStatus.FetchFailed, "", null);
        }
        if (resp.StatusCode == HttpStatusCode.NotFound)
        {
            // Distinguish "file gone, repo present" from "repo gone".
            using var repoResp = await _http.GetAsync($"/repos/{repoFullName}", ct);
            return new RefetchResult(
                repoResp.IsSuccessStatusCode ? RefetchStatus.FileGone : RefetchStatus.RepoGone,
                "", null);
        }
        if (resp.StatusCode == (HttpStatusCode)451)
        {
            return new RefetchResult(RefetchStatus.RepoGone, "", null);
        }
        if (!resp.IsSuccessStatusCode)
        {
            return new RefetchResult(RefetchStatus.FetchFailed, "", null);
        }

        var payload = await resp.Content.ReadFromJsonAsync<ContentsResponse>(
            cancellationToken: ct);
        if (payload is null) return new RefetchResult(RefetchStatus.FetchFailed, "", null);
        var content = ToResult(payload);
        return new RefetchResult(RefetchStatus.Present, content.Content, content.CommitSha);
    }

    /// <summary>
    /// Open an issue on a public repo. The body is plain markdown — no
    /// secret content; we don't have the key, only its hash and prefix.
    /// Returns the issue's number and html_url for the notices row.
    /// </summary>
    public async Task<IssueResult> OpenIssueAsync(
        string repoFullName, string title, string body, CancellationToken ct = default)
    {
        var url = $"/repos/{repoFullName}/issues";
        var payload = new IssueCreateRequest(title, body);
        using var resp = await _http.PostAsJsonAsync(url, payload, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var err = await resp.Content.ReadAsStringAsync(ct);
            return new IssueResult(false, null, null, $"{(int)resp.StatusCode}: {err}");
        }

        var created = await resp.Content.ReadFromJsonAsync<IssueCreateResponse>(
            cancellationToken: ct);
        return new IssueResult(true, created?.Number, created?.HtmlUrl, null);
    }

    private static FileContentResult ToResult(ContentsResponse payload)
    {
        var raw = "";
        if (payload.Encoding == "base64" && !string.IsNullOrEmpty(payload.Content))
        {
            try
            {
                // GitHub breaks base64 across lines.
                var cleaned = payload.Content.Replace("\n", "").Replace("\r", "");
                raw = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(cleaned));
            }
            catch (FormatException ex)
            {
                Console.Error.WriteLine($"[github] base64 decode failed (sha={payload.Sha}): {ex.Message}");
                raw = "";
            }
        }
        return new FileContentResult(raw, payload.Sha);
    }

    private static async Task HandleRateLimitAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        // Priority order matches GitHub docs:
        //   1) Retry-After header (secondary limits set this in seconds)
        //   2) X-RateLimit-Remaining=0 + X-RateLimit-Reset (primary)
        //   3) fallback exponential-ish back-off
        // The handler never throws or propagates the 403 — the loop mode
        // counts on this so a long-running daemon doesn't crash mid-scan.
        if (resp.Headers.TryGetValues("Retry-After", out var ra)
            && int.TryParse(ra.FirstOrDefault(), out var retryAfter)
            && retryAfter > 0)
        {
            // Cap at 1 hour so a misconfigured server can't hang us.
            var wait = Math.Min(retryAfter + 1, 3600);
            Console.Error.WriteLine($"[rate-limit] retry-after={retryAfter}s; sleeping {wait}s");
            await SafeDelayAsync(TimeSpan.FromSeconds(wait), ct);
            return;
        }

        var remaining = resp.Headers.TryGetValues("X-RateLimit-Remaining", out var r)
            ? r.FirstOrDefault() : null;
        var reset = resp.Headers.TryGetValues("X-RateLimit-Reset", out var s)
            ? s.FirstOrDefault() : null;
        if (remaining == "0" && long.TryParse(reset, out var resetUnix))
        {
            var wait = resetUnix - DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 1;
            if (wait > 0)
            {
                wait = Math.Min(wait, 3600);
                Console.Error.WriteLine($"[rate-limit] primary exhausted; sleeping {wait}s");
                await SafeDelayAsync(TimeSpan.FromSeconds(wait), ct);
                return;
            }
        }

        // Secondary rate limit without a Retry-After header: GitHub asks
        // for "a few minutes." 60s is the documented minimum back-off.
        Console.Error.WriteLine("[rate-limit] secondary (no header); sleeping 60s");
        await SafeDelayAsync(TimeSpan.FromSeconds(60), ct);
    }

    private static async Task SafeDelayAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct); }
        catch (OperationCanceledException) { /* shutdown — bubble up via ct */ }
    }

    public void Dispose() => _http.Dispose();
}

public sealed record FileContentResult(string Content, string? CommitSha);

public enum RefetchStatus
{
    Present,
    FileGone,
    RepoGone,
    FetchFailed,
}

public sealed record RefetchResult(RefetchStatus Status, string Content, string? CommitSha);

public sealed record IssueResult(bool Ok, int? Number, string? HtmlUrl, string? Error);

public sealed class IssueCreateRequest
{
    [JsonPropertyName("title")] public string Title { get; }
    [JsonPropertyName("body")] public string Body { get; }
    public IssueCreateRequest(string title, string body) { Title = title; Body = body; }
}

public sealed class IssueCreateResponse
{
    [JsonPropertyName("number")] public int? Number { get; set; }
    [JsonPropertyName("html_url")] public string? HtmlUrl { get; set; }
}

public sealed class CodeSearchResponse
{
    [JsonPropertyName("items")] public CodeSearchItem[]? Items { get; set; }
}

public sealed class CodeSearchItem
{
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("html_url")] public string HtmlUrl { get; set; } = "";
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("repository")] public RepoInfo? Repository { get; set; }
}

public sealed class RepoInfo
{
    [JsonPropertyName("full_name")] public string FullName { get; set; } = "";
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("html_url")] public string HtmlUrl { get; set; } = "";
    [JsonPropertyName("default_branch")] public string? DefaultBranch { get; set; }
    [JsonPropertyName("owner")] public OwnerInfo? Owner { get; set; }
}

public sealed class OwnerInfo
{
    [JsonPropertyName("login")] public string? Login { get; set; }
}

public sealed class ContentsResponse
{
    [JsonPropertyName("encoding")] public string? Encoding { get; set; }
    [JsonPropertyName("content")] public string? Content { get; set; }
    [JsonPropertyName("sha")] public string? Sha { get; set; }
}
