using System.Net;
using System.Text;

namespace FractionsOfAPenny;

/// <summary>
/// Self-contained HTML report generator. Emits a static file with inline
/// CSS and no JavaScript. No raw API keys appear — each record is
/// represented only by the SHA-256 hash and the 16-char scheme prefix
/// already stored in Finding.
/// </summary>
public static class Report
{
    private static readonly Dictionary<string, string> ProviderLabels = new()
    {
        ["anthropic"] = "Anthropic",
        ["openai"] = "OpenAI (project)",
        ["openai-legacy"] = "OpenAI (legacy)",
        ["google-gemini"] = "Google Gemini",
    };

    public static FileInfo Write(IReadOnlyList<Finding> findings, FileInfo jsonOut)
    {
        var htmlPath = Path.ChangeExtension(jsonOut.FullName, ".htm");
        File.WriteAllText(htmlPath, Render(findings), new UTF8Encoding(false));
        return new FileInfo(htmlPath);
    }

    public static string Render(IReadOnlyList<Finding> findings)
    {
        var total = findings.Count;
        var byProvider = findings
            .GroupBy(f => f.Provider)
            .Select(g => (key: g.Key, count: g.Count()))
            .OrderByDescending(x => x.count)
            .ToList();
        var byModel = findings
            .GroupBy(f => f.ModelHint ?? "(unknown)")
            .Select(g => (key: g.Key, count: g.Count()))
            .OrderByDescending(x => x.count)
            .Take(20)
            .ToList();
        var byAuthor = findings
            .GroupBy(f => f.AuthorLogin ?? "(unknown)")
            .Select(g => (key: g.Key, count: g.Count()))
            .OrderByDescending(x => x.count)
            .Take(15)
            .ToList();
        var uniqueRepos = findings
            .Where(f => !string.IsNullOrEmpty(f.RepoFullName))
            .Select(f => f.RepoFullName)
            .Distinct()
            .Count();
        var uniqueKeys = findings
            .Where(f => !string.IsNullOrEmpty(f.KeySha256))
            .Select(f => f.KeySha256)
            .Distinct()
            .Count();
        var generated = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm") + " UTC";

        var tiles = new StringBuilder();
        tiles.Append(Card("Findings", total.ToString()));
        tiles.Append(Card("Unique keys", uniqueKeys.ToString()));
        tiles.Append(Card("Unique repos", uniqueRepos.ToString()));
        foreach (var (k, c) in byProvider)
        {
            var label = ProviderLabels.TryGetValue(k, out var l) ? l : k;
            tiles.Append(Card(label, c.ToString()));
        }

        var modelMax = byModel.Count > 0 ? byModel[0].count : 1;
        var modelRows = new StringBuilder();
        foreach (var (k, c) in byModel) modelRows.Append(BarRow(k, c, modelMax));

        var authorMax = byAuthor.Count > 0 ? byAuthor[0].count : 1;
        var authorRows = new StringBuilder();
        foreach (var (k, c) in byAuthor) authorRows.Append(BarRow(k, c, authorMax));

        var tableRows = new StringBuilder();
        foreach (var f in findings.OrderByDescending(x => x.DetectedAtUtc ?? ""))
        {
            tableRows.Append(FindingRow(f));
        }

        var emptyRow3 = "<tr><td colspan=\"3\" class=\"muted\">no data</td></tr>";
        var emptyRow9 = "<tr><td colspan=\"9\" class=\"muted\">no findings</td></tr>";

        return $$"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FractionsOfAPenny — Findings Report</title>
<style>
  :root { color-scheme: light dark;
          --bg:#0b0d10; --fg:#e6e6e6; --card:#151a20; --muted:#8a9099;
          --accent:#6ea8fe; --warn:#f4a261; --border:#252a31; }
  @media (prefers-color-scheme: light) {
    :root { --bg:#fafbfc; --fg:#1a1f24; --card:#fff; --muted:#5a6470;
            --accent:#0a66c2; --warn:#b35900; --border:#e3e7eb; }
  }
  html,body { margin:0; padding:0; }
  body { font:14px/1.5 -apple-system,"Segoe UI",Inter,system-ui,sans-serif;
         background:var(--bg); color:var(--fg); }
  header { padding:24px 32px; border-bottom:1px solid var(--border); }
  h1 { margin:0 0 4px; font-size:20px; font-weight:600; }
  .subtitle { color:var(--muted); font-size:13px; }
  main { padding:24px 32px; max-width:1400px; margin:0 auto; }
  section { margin-bottom:32px; }
  section h2 { font-size:11px; font-weight:600; margin:0 0 12px;
               color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; }
  .card { background:var(--card); border:1px solid var(--border);
          border-radius:8px; padding:12px 14px; }
  .card .label { color:var(--muted); font-size:11px; text-transform:uppercase;
                 letter-spacing:.05em; }
  .card .value { font-size:22px; font-weight:600; margin-top:2px; }
  table { border-collapse:collapse; width:100%; background:var(--card);
          border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  th,td { padding:8px 10px; text-align:left; border-bottom:1px solid var(--border);
          vertical-align:middle; font-size:13px; }
  th { background:color-mix(in srgb,var(--card) 40%,var(--border));
       font-weight:600; font-size:11px; text-transform:uppercase;
       letter-spacing:.05em; color:var(--muted); }
  td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
  td.barcell { width:45%; }
  tr:last-child td { border-bottom:none; }
  tbody tr:hover { background:color-mix(in srgb,var(--accent) 6%,transparent); }
  a { color:var(--accent); text-decoration:none; }
  a:hover { text-decoration:underline; }
  code, .mono { font:12px/1.4 "SF Mono","JetBrains Mono",Consolas,monospace;
                color:var(--muted); }
  .truncate { display:inline-block; max-width:320px; overflow:hidden;
              text-overflow:ellipsis; white-space:nowrap; vertical-align:bottom; }
  .pill { display:inline-block; padding:2px 8px; border-radius:999px;
          background:color-mix(in srgb,var(--accent) 16%,transparent);
          color:var(--accent); font-size:11px; font-weight:600;
          text-transform:uppercase; letter-spacing:.04em; }
  .pill.anthropic { background:color-mix(in srgb,#c96442 18%,transparent); color:#c96442; }
  .pill.openai { background:color-mix(in srgb,#10a37f 18%,transparent); color:#10a37f; }
  .pill.openai-legacy { background:color-mix(in srgb,var(--warn) 18%,transparent); color:var(--warn); }
  .pill.google-gemini { background:color-mix(in srgb,#4285f4 18%,transparent); color:#4285f4; }
  .bar { background:var(--border); border-radius:3px; height:8px; width:100%; overflow:hidden; }
  .bar > div { background:var(--accent); height:100%; }
  .banner { background:color-mix(in srgb,var(--warn) 12%,transparent);
            color:var(--warn);
            border:1px solid color-mix(in srgb,var(--warn) 40%,transparent);
            border-radius:8px; padding:10px 14px; margin-bottom:24px; font-size:13px; }
  .split { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  @media (max-width:900px) { .split { grid-template-columns:1fr; } }
  .muted { color:var(--muted); }
</style>
</head>
<body>
<header>
  <h1>FractionsOfAPenny — Leaked-Credential Prevalence</h1>
  <div class="subtitle">Metadata-only research dataset · generated {{E(generated)}} · {{total}} findings</div>
</header>
<main>
  <div class="banner">Non-retention: no raw API keys appear in this report. Each key is represented only by a SHA-256 hash and a 16-char scheme prefix.</div>

  <section>
    <h2>Summary</h2>
    <div class="grid">{{tiles}}</div>
  </section>

  <section>
    <h2>Distribution</h2>
    <div class="split">
      <div>
        <table>
          <thead><tr><th>Model</th><th class="num">Count</th><th>Share</th></tr></thead>
          <tbody>{{(modelRows.Length > 0 ? modelRows.ToString() : emptyRow3)}}</tbody>
        </table>
      </div>
      <div>
        <table>
          <thead><tr><th>Author</th><th class="num">Count</th><th>Share</th></tr></thead>
          <tbody>{{(authorRows.Length > 0 ? authorRows.ToString() : emptyRow3)}}</tbody>
        </table>
      </div>
    </div>
  </section>

  <section>
    <h2>Findings ({{total}})</h2>
    <table>
      <thead><tr>
        <th>Provider</th><th>Model</th><th>Repo</th><th>Author</th><th>File</th>
        <th>Prefix</th><th class="num">Len</th><th>SHA-256</th><th>Detected (UTC)</th>
      </tr></thead>
      <tbody>{{(tableRows.Length > 0 ? tableRows.ToString() : emptyRow9)}}</tbody>
    </table>
  </section>
</main>
</body>
</html>
""";
    }

    private static string Card(string label, string value) =>
        $"<div class=\"card\"><div class=\"label\">{E(label)}</div>" +
        $"<div class=\"value\">{E(value)}</div></div>";

    private static string BarRow(string label, int n, int max)
    {
        var pct = max > 0 ? (n * 100.0 / max) : 0;
        return $"<tr><td>{E(label)}</td>" +
               $"<td class=\"num\">{n}</td>" +
               $"<td class=\"barcell\"><div class=\"bar\"><div style=\"width:{pct:F1}%\"></div></div></td></tr>";
    }

    private static string FindingRow(Finding f)
    {
        var provider = E(f.Provider);
        var sha = f.KeySha256 ?? "";
        var shortSha = sha.Length > 12 ? sha[..12] : sha;
        var detected = (f.DetectedAtUtc ?? "");
        if (detected.Length > 19) detected = detected[..19];
        detected = detected.Replace('T', ' ');
        return "<tr>" +
               $"<td><span class=\"pill {provider}\">{provider}</span></td>" +
               $"<td>{E(f.ModelHint ?? "—")}</td>" +
               $"<td><a href=\"{E(f.RepoHtmlUrl)}\" target=\"_blank\" rel=\"noopener\">{E(f.RepoFullName)}</a></td>" +
               $"<td>{E(f.AuthorLogin ?? "—")}</td>" +
               $"<td><a class=\"mono\" href=\"{E(f.FileHtmlUrl)}\" target=\"_blank\" rel=\"noopener\">" +
               $"<span class=\"truncate\">{E(f.FilePath)}</span></a></td>" +
               $"<td class=\"mono\">{E(f.KeyPrefix)}…</td>" +
               $"<td class=\"num mono\">{f.KeyLength}</td>" +
               $"<td class=\"mono\" title=\"{E(sha)}\">{E(shortSha)}…</td>" +
               $"<td class=\"mono\">{E(detected)}</td>" +
               "</tr>";
    }

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
}
