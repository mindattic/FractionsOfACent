using System.Globalization;

namespace FractionsOfACent.Blazor;

/// <summary>
/// One snapshot of all numbers the Visualizations page needs. Computed
/// once per page render — the queries are small enough on a typical
/// research dataset that we don't bother caching.
/// </summary>
public sealed class VizData
{
    public required int TotalFindings { get; init; }
    public required int TotalNotices { get; init; }
    public required int TotalRemediated { get; init; }
    public double PercentRemediated =>
        TotalFindings == 0 ? 0 : 100.0 * TotalRemediated / TotalFindings;
    public double? AvgDaysToRemediate { get; init; }
    public double? AvgChecksToRemediate { get; init; }
    public required CumulativeSeries CumulativeSeries { get; init; }
    public required IReadOnlyList<HistogramBucket> RemediationDayBuckets { get; init; }
    public required IReadOnlyList<HistogramBucket> RemediationCheckBuckets { get; init; }
    public required IReadOnlyList<ProviderRow> ProviderBreakdown { get; init; }
    public required IReadOnlyList<DonutSlice> StatusMix { get; init; }
    public required IReadOnlyList<DonutSlice> RepoExposureMix { get; init; }
    public required int ReposScanned { get; init; }
    public required int ReposWithFindings { get; init; }

    public static VizData Compute(Db db)
    {
        var findings = db.AllFindings();
        var notices = db.AllNotices();
        var checks = db.AllRemediationChecks();
        var latest = db.LatestRemediationChecks();
        var (reposScanned, reposWithFindings) = db.RepoScanCounts();

        var remediatedKeys = latest
            .Where(kv => kv.Value.Status is "removed" or "repo_gone" or "file_gone")
            .Select(kv => kv.Key)
            .ToHashSet();

        var (avgDays, avgChecks) = ComputeRemediationAverages(
            findings, checks, remediatedKeys);

        return new VizData
        {
            TotalFindings = findings.Count,
            TotalNotices = notices.Count(n => n.Status == "sent"),
            TotalRemediated = remediatedKeys.Count,
            AvgDaysToRemediate = avgDays,
            AvgChecksToRemediate = avgChecks,
            CumulativeSeries = BuildCumulative(findings, notices, checks, remediatedKeys),
            RemediationDayBuckets = BuildDayHistogram(findings, checks, remediatedKeys),
            RemediationCheckBuckets = BuildCheckHistogram(checks, remediatedKeys),
            ProviderBreakdown = BuildProviderBreakdown(findings, notices, latest),
            StatusMix = BuildStatusMix(findings, latest),
            RepoExposureMix = BuildRepoExposureMix(reposScanned, reposWithFindings),
            ReposScanned = reposScanned,
            ReposWithFindings = reposWithFindings,
        };
    }

    private static IReadOnlyList<DonutSlice> BuildRepoExposureMix(
        int reposScanned, int reposWithFindings)
    {
        var clean = Math.Max(0, reposScanned - reposWithFindings);
        return new List<DonutSlice>
        {
            new("No credentials found", clean),
            new("Credentials found", reposWithFindings),
        };
    }

    private static DateTime? ParseUtc(string? iso) =>
        DateTime.TryParse(iso, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var dt) ? dt : null;

    private static (double? days, double? checks) ComputeRemediationAverages(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<RemediationCheck> checks,
        HashSet<(string, string, string)> remediatedKeys)
    {
        if (remediatedKeys.Count == 0) return (null, null);

        var firstSeenByKey = findings.ToDictionary(
            f => (f.KeySha256, f.RepoFullName, f.FilePath),
            f => ParseUtc(f.FirstSeenUtc));

        var firstRemovedByKey = checks
            .Where(c => c.Status is "removed" or "repo_gone" or "file_gone")
            .GroupBy(c => (c.KeySha256, c.RepoFullName, c.FilePath))
            .ToDictionary(g => g.Key, g => ParseUtc(g.Min(c => c.CheckedAtUtc)));

        var checkCountToRemediate = checks
            .GroupBy(c => (c.KeySha256, c.RepoFullName, c.FilePath))
            .Where(g => remediatedKeys.Contains(g.Key))
            .Select(g =>
            {
                // Count check rows up to and including the first 'removed' row.
                var ordered = g.OrderBy(c => c.CheckedAtUtc).ToList();
                var idx = ordered.FindIndex(c =>
                    c.Status is "removed" or "repo_gone" or "file_gone");
                return idx < 0 ? ordered.Count : idx + 1;
            })
            .ToList();

        var daySpans = new List<double>();
        foreach (var key in remediatedKeys)
        {
            if (firstSeenByKey.TryGetValue(key, out var seen) && seen.HasValue
                && firstRemovedByKey.TryGetValue(key, out var removed) && removed.HasValue)
            {
                daySpans.Add((removed.Value - seen.Value).TotalDays);
            }
        }

        return (
            daySpans.Count > 0 ? daySpans.Average() : null,
            checkCountToRemediate.Count > 0 ? checkCountToRemediate.Average() : null);
    }

    private static CumulativeSeries BuildCumulative(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<Notice> notices,
        IReadOnlyList<RemediationCheck> checks,
        HashSet<(string, string, string)> remediatedKeys)
    {
        var findingDates = findings
            .Select(f => ParseUtc(f.FirstSeenUtc)?.Date)
            .Where(d => d.HasValue).Select(d => d!.Value).OrderBy(d => d).ToList();
        var noticeDates = notices
            .Where(n => n.Status == "sent")
            .Select(n => ParseUtc(n.SentAtUtc)?.Date)
            .Where(d => d.HasValue).Select(d => d!.Value).OrderBy(d => d).ToList();
        var remDates = checks
            .Where(c => c.Status is "removed" or "repo_gone" or "file_gone")
            .GroupBy(c => (c.KeySha256, c.RepoFullName, c.FilePath))
            .Where(g => remediatedKeys.Contains(g.Key))
            .Select(g => ParseUtc(g.Min(c => c.CheckedAtUtc))?.Date)
            .Where(d => d.HasValue).Select(d => d!.Value).OrderBy(d => d).ToList();

        if (findingDates.Count == 0)
        {
            return new CumulativeSeries(
                Array.Empty<DateTime>(),
                Array.Empty<int>(), Array.Empty<int>(), Array.Empty<int>());
        }

        var start = findingDates.First();
        var end = DateTime.UtcNow.Date;
        if (noticeDates.Count > 0 && noticeDates.Last() > end) end = noticeDates.Last();
        if (remDates.Count > 0 && remDates.Last() > end) end = remDates.Last();

        var days = new List<DateTime>();
        for (var d = start; d <= end; d = d.AddDays(1)) days.Add(d);

        int[] cum(IList<DateTime> sorted)
        {
            var arr = new int[days.Count];
            var idx = 0;
            for (var i = 0; i < days.Count; i++)
            {
                while (idx < sorted.Count && sorted[idx] <= days[i]) idx++;
                arr[i] = idx;
            }
            return arr;
        }

        return new CumulativeSeries(
            days, cum(findingDates), cum(noticeDates), cum(remDates));
    }

    private static IReadOnlyList<HistogramBucket> BuildDayHistogram(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<RemediationCheck> checks,
        HashSet<(string, string, string)> remediatedKeys)
    {
        var firstSeen = findings.ToDictionary(
            f => (f.KeySha256, f.RepoFullName, f.FilePath),
            f => ParseUtc(f.FirstSeenUtc));
        var firstRemoved = checks
            .Where(c => c.Status is "removed" or "repo_gone" or "file_gone")
            .GroupBy(c => (c.KeySha256, c.RepoFullName, c.FilePath))
            .Where(g => remediatedKeys.Contains(g.Key))
            .ToDictionary(g => g.Key, g => ParseUtc(g.Min(c => c.CheckedAtUtc)));

        var days = new List<double>();
        foreach (var key in remediatedKeys)
        {
            if (firstSeen.TryGetValue(key, out var s) && s.HasValue
                && firstRemoved.TryGetValue(key, out var r) && r.HasValue)
            {
                days.Add((r.Value - s.Value).TotalDays);
            }
        }
        return Bucketize(days, [0, 1, 3, 7, 14, 30, 90]);
    }

    private static IReadOnlyList<HistogramBucket> BuildCheckHistogram(
        IReadOnlyList<RemediationCheck> checks,
        HashSet<(string, string, string)> remediatedKeys)
    {
        var counts = checks
            .GroupBy(c => (c.KeySha256, c.RepoFullName, c.FilePath))
            .Where(g => remediatedKeys.Contains(g.Key))
            .Select(g =>
            {
                var ordered = g.OrderBy(c => c.CheckedAtUtc).ToList();
                var idx = ordered.FindIndex(c =>
                    c.Status is "removed" or "repo_gone" or "file_gone");
                return (double)(idx < 0 ? ordered.Count : idx + 1);
            })
            .ToList();
        return Bucketize(counts, [1, 2, 3, 5, 10, 20]);
    }

    private static IReadOnlyList<HistogramBucket> Bucketize(
        IList<double> values, double[] edges)
    {
        var result = new List<HistogramBucket>();
        for (var i = 0; i < edges.Length; i++)
        {
            var lo = edges[i];
            var hi = i + 1 < edges.Length ? edges[i + 1] : double.PositiveInfinity;
            var label = double.IsPositiveInfinity(hi) ? $"{lo:N0}+"
                : i == 0 ? $"≤{hi:N0}"
                : $"{lo:N0}–{hi:N0}";
            var count = values.Count(v => v >= lo && v < hi);
            result.Add(new HistogramBucket(label, count));
        }
        return result;
    }

    private static IReadOnlyList<ProviderRow> BuildProviderBreakdown(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<Notice> notices,
        Dictionary<(string, string, string), RemediationCheck> latest)
    {
        var noticedKeys = notices.Where(n => n.Status == "sent")
            .Select(n => (n.KeySha256, n.RepoFullName, n.FilePath))
            .ToHashSet();
        var remediatedKeys = latest
            .Where(kv => kv.Value.Status is "removed" or "repo_gone" or "file_gone")
            .Select(kv => kv.Key)
            .ToHashSet();

        return findings
            .GroupBy(f => f.Provider)
            .Select(g => new ProviderRow(
                Provider: g.Key,
                Total: g.Count(),
                Noticed: g.Count(f =>
                    noticedKeys.Contains((f.KeySha256, f.RepoFullName, f.FilePath))),
                Remediated: g.Count(f =>
                    remediatedKeys.Contains((f.KeySha256, f.RepoFullName, f.FilePath)))))
            .OrderByDescending(r => r.Total)
            .ToList();
    }

    private static IReadOnlyList<DonutSlice> BuildStatusMix(
        IReadOnlyList<Finding> findings,
        Dictionary<(string, string, string), RemediationCheck> latest)
    {
        var statusCounts = new Dictionary<string, int>
        {
            ["unchecked"] = 0,
            ["present"] = 0,
            ["removed"] = 0,
            ["file_gone"] = 0,
            ["repo_gone"] = 0,
            ["fetch_failed"] = 0,
        };
        foreach (var f in findings)
        {
            var key = (f.KeySha256, f.RepoFullName, f.FilePath);
            var status = latest.TryGetValue(key, out var rc) ? rc.Status : "unchecked";
            statusCounts[status] = statusCounts.GetValueOrDefault(status) + 1;
        }
        return statusCounts
            .Where(kv => kv.Value > 0)
            .Select(kv => new DonutSlice(kv.Key, kv.Value))
            .ToList();
    }
}

public sealed record CumulativeSeries(
    IReadOnlyList<DateTime> Days,
    IReadOnlyList<int> Findings,
    IReadOnlyList<int> Notices,
    IReadOnlyList<int> Remediations);

public sealed record HistogramBucket(string Label, int Count);

public sealed record ProviderRow(string Provider, int Total, int Noticed, int Remediated);

public sealed record DonutSlice(string Label, int Count);
