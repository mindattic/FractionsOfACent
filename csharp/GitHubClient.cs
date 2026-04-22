using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FractionsOfAPenny;

public sealed class GitHubClient : IDisposable
{
    private const string ApiBase = "https://api.github.com";
    private const string UserAgent = "fractions-of-a-penny-research/0.1 (+academic study, metadata-only)";

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

        var raw = "";
        if (payload.Encoding == "base64" && !string.IsNullOrEmpty(payload.Content))
        {
            try
            {
                // GitHub breaks base64 across lines.
                var cleaned = payload.Content.Replace("\n", "").Replace("\r", "");
                raw = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(cleaned));
            }
            catch
            {
                raw = "";
            }
        }
        return new FileContentResult(raw, payload.Sha);
    }

    private static async Task HandleRateLimitAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        var remaining = resp.Headers.TryGetValues("X-RateLimit-Remaining", out var r)
            ? r.FirstOrDefault() : null;
        var reset = resp.Headers.TryGetValues("X-RateLimit-Reset", out var s)
            ? s.FirstOrDefault() : null;
        if (remaining == "0" && long.TryParse(reset, out var resetUnix))
        {
            var wait = resetUnix - DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 1;
            if (wait > 0)
            {
                Console.Error.WriteLine($"[rate-limit] sleeping {wait}s");
                await Task.Delay(TimeSpan.FromSeconds(wait), ct);
                return;
            }
        }
        // Secondary rate-limit fallback.
        await Task.Delay(TimeSpan.FromSeconds(10), ct);
    }

    public void Dispose() => _http.Dispose();
}

public sealed record FileContentResult(string Content, string? CommitSha);

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
