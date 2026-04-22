using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FractionsOfAPenny;

public sealed class Scraper
{
    private const int ContextRadius = 200;

    private readonly GitHubClient _client;
    private readonly FileInfo _outFile;
    private readonly int _maxPerProvider;

    public Scraper(GitHubClient client, FileInfo outFile, int maxPerProvider)
    {
        _client = client;
        _outFile = outFile;
        _maxPerProvider = maxPerProvider;
    }

    public async Task<int> RunAsync(string[]? providerFilter, CancellationToken ct)
    {
        var existing = LoadExisting();
        // Dedup by (key, repo, path) so the same leak at a new commit SHA
        // does not re-catalog. FileHtmlUrl contains the indexing-time
        // commit SHA, which drifts between runs.
        var seen = new HashSet<(string, string, string)>(
            existing.Select(f => (f.KeySha256, f.RepoFullName, f.FilePath)));
        var all = new List<Finding>(existing);
        var totalNew = 0;

        foreach (var pat in Patterns.All)
        {
            if (providerFilter is { Length: > 0 }
                && !providerFilter.Contains(pat.Provider))
            {
                continue;
            }

            Console.Error.WriteLine(
                $"[scan] provider={pat.Provider} needle={pat.SearchNeedle}");
            var foundForProvider = 0;

            await foreach (var item in _client.SearchCodeAsync(pat.SearchNeedle, ct: ct))
            {
                if (foundForProvider >= _maxPerProvider) break;

                try
                {
                    await foreach (var finding in ScanItemAsync(item, pat, ct))
                    {
                        var id = (finding.KeySha256, finding.RepoFullName, finding.FilePath);
                        if (!seen.Add(id)) continue;
                        all.Add(finding);
                        totalNew++;
                        foundForProvider++;
                        Console.Error.WriteLine(
                            $"  {finding.Provider} {finding.RepoFullName}#{finding.FilePath} " +
                            $"({finding.ModelHint ?? "model=?"})");
                        if (foundForProvider >= _maxPerProvider) break;
                    }
                }
                catch (HttpRequestException e)
                {
                    Console.Error.WriteLine($"[warn] fetch failed: {e.Message}");
                }

                await Task.Delay(TimeSpan.FromMilliseconds(500), ct);
            }

            Persist(all);
            Console.Error.WriteLine(
                $"[scan] provider={pat.Provider} new={foundForProvider} total={totalNew}");
        }

        var htmlFile = Report.Write(all, _outFile);
        Console.Error.WriteLine(
            $"[done] new findings: {totalNew}, total in {_outFile.Name}: {all.Count}");
        Console.Error.WriteLine($"[report] {htmlFile.FullName}");
        return totalNew;
    }

    private async IAsyncEnumerable<Finding> ScanItemAsync(
        CodeSearchItem item,
        ProviderPattern pat,
        [System.Runtime.CompilerServices.EnumeratorCancellation]
        CancellationToken ct)
    {
        var result = await _client.FetchFileAsync(item, ct);
        if (string.IsNullOrEmpty(result.Content)) yield break;

        var localSeen = new HashSet<string>();
        foreach (Match m in pat.Regex.Matches(result.Content))
        {
            // rawKey leaves scope at the end of the loop body. It is used
            // only to compute the SHA-256 hash and prefix; never logged,
            // never persisted, never returned.
            var rawKey = m.Value;
            var (sha256, prefix, length) = Fingerprint(rawKey);
            rawKey = null!; // drop reference explicitly

            if (!localSeen.Add(sha256)) continue;

            var start = m.Index;
            var end = start + m.Length;
            var ctxStart = Math.Max(0, start - ContextRadius);
            var ctxEnd = Math.Min(result.Content.Length, end + ContextRadius);
            var context = result.Content.Substring(ctxStart, ctxEnd - ctxStart);
            var model = Patterns.InferModel(context, pat.ModelHints);

            var repo = item.Repository;
            yield return new Finding(
                Provider: pat.Provider,
                ModelHint: model,
                RepoFullName: repo?.FullName ?? "",
                RepoUrl: repo?.Url ?? "",
                RepoHtmlUrl: repo?.HtmlUrl ?? "",
                AuthorLogin: repo?.Owner?.Login,
                FilePath: item.Path,
                FileHtmlUrl: item.HtmlUrl,
                CommitSha: result.CommitSha,
                DefaultBranch: repo?.DefaultBranch,
                DetectedAtUtc: DateTime.UtcNow.ToString("O"),
                KeySha256: sha256,
                KeyPrefix: prefix,
                KeyLength: length);
        }
    }

    private static (string sha256, string prefix, int length) Fingerprint(string key)
    {
        var bytes = Encoding.UTF8.GetBytes(key);
        var hash = SHA256.HashData(bytes);
        var sha = Convert.ToHexString(hash).ToLowerInvariant();
        var prefixLen = Math.Min(16, key.Length);
        var prefix = key[..prefixLen];
        return (sha, prefix, key.Length);
    }

    private List<Finding> LoadExisting()
    {
        if (!_outFile.Exists) return [];
        try
        {
            var json = File.ReadAllText(_outFile.FullName);
            return JsonSerializer.Deserialize<List<Finding>>(json, JsonOpts) ?? [];
        }
        catch (JsonException)
        {
            Console.Error.WriteLine($"[warn] could not parse {_outFile.Name}; starting fresh");
            return [];
        }
    }

    private void Persist(List<Finding> all)
    {
        var json = JsonSerializer.Serialize(all, JsonOpts);
        File.WriteAllText(_outFile.FullName, json);
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };
}
