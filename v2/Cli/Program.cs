using FractionsOfACent;

var outPath = "findings.db";
var maxPerProvider = 50;
var maxRechecks = 100;
var maxNotices = 25;
var includePasswords = false;
var loopIntervalSeconds = 0;
var providerFilter = new List<string>();
var verbose = false;

for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--out":
            outPath = args[++i];
            break;
        case "--max-per-provider":
            maxPerProvider = int.Parse(args[++i]);
            break;
        case "--max-rechecks":
            maxRechecks = int.Parse(args[++i]);
            break;
        case "--no-recheck":
            maxRechecks = 0;
            break;
        case "--max-notices":
            maxNotices = int.Parse(args[++i]);
            break;
        case "--no-notify":
            maxNotices = 0;
            break;
        case "--include-passwords":
            includePasswords = true;
            break;
        case "--loop":
            loopIntervalSeconds = ParseDuration(args[++i]);
            break;
        case "--provider":
            providerFilter.Add(args[++i]);
            break;
        case "-v":
        case "--verbose":
            verbose = true;
            break;
        case "-h":
        case "--help":
            PrintHelp();
            return 0;
        default:
            Console.Error.WriteLine($"unknown arg: {args[i]}");
            PrintHelp();
            return 2;
    }
}

var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
if (string.IsNullOrWhiteSpace(token))
{
    token = Settings.LoadGitHubToken();
}
if (string.IsNullOrWhiteSpace(token))
{
    Console.Error.WriteLine(
        "error: GitHub PAT not found. Set GITHUB_TOKEN env var, or put");
    Console.Error.WriteLine($"  {{ \"github_token\": \"github_pat_...\" }}");
    Console.Error.WriteLine($"  into {Settings.ConfigPath}");
    return 2;
}

if (verbose) Console.Error.WriteLine($"[config] out={outPath} max={maxPerProvider}");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

using var client = new GitHubClient(token);
var scraper = new Scraper(
    client, new FileInfo(outPath),
    maxPerProvider, maxRechecks, maxNotices, includePasswords);
var providerArr = providerFilter.Count > 0 ? providerFilter.ToArray() : null;

if (loopIntervalSeconds > 0)
{
    Console.Error.WriteLine(
        $"[loop] running every {loopIntervalSeconds}s; Ctrl-C to stop");
    var pass = 0;
    while (!cts.IsCancellationRequested)
    {
        pass++;
        Console.Error.WriteLine($"[loop] pass #{pass}");
        try { await scraper.RunAsync(providerArr, cts.Token); }
        catch (OperationCanceledException) { break; }
        catch (Exception e)
        {
            // The scraper internally absorbs rate-limit and HTTP errors
            // and never throws on them; this catch is for genuinely
            // unexpected exceptions (DB locked, OOM, etc.). Log and keep
            // looping — the user explicitly wants indefinite operation.
            Console.Error.WriteLine($"[loop] pass failed: {e.Message}");
        }
        if (cts.IsCancellationRequested) break;
        Console.Error.WriteLine($"[loop] sleeping {loopIntervalSeconds}s");
        try { await Task.Delay(TimeSpan.FromSeconds(loopIntervalSeconds), cts.Token); }
        catch (OperationCanceledException) { break; }
    }
}
else
{
    await scraper.RunAsync(providerArr, cts.Token);
}
return 0;

static int ParseDuration(string s)
{
    // Accepts plain seconds ("60") or suffix forms: "30s", "5m", "1h".
    if (string.IsNullOrEmpty(s)) return 0;
    var last = s[^1];
    if (char.IsDigit(last)) return int.Parse(s);
    var n = int.Parse(s[..^1]);
    return last switch
    {
        's' or 'S' => n,
        'm' or 'M' => n * 60,
        'h' or 'H' => n * 3600,
        'd' or 'D' => n * 86400,
        _ => throw new ArgumentException($"bad duration: {s}"),
    };
}

static void PrintHelp()
{
    Console.WriteLine("""
        fractions — leaked-credential prevalence scanner (metadata only)

        Usage:
          fractions [--out findings.db] [--max-per-provider N]
                    [--max-rechecks N | --no-recheck]
                    [--max-notices N  | --no-notify]
                    [--include-passwords]
                    [--loop INTERVAL]
                    [--provider anthropic] [--provider github-pat-classic ...]
                    [-v]

        Pipeline (each run): scan → notify → recheck remediation. By default,
        every exposure type has auto_inform=false, so notify is a no-op until
        you flip a category on in the Web UI; you can also send notices
        manually per-finding from there.

        --loop INTERVAL    runs the full pipeline indefinitely, sleeping
                           INTERVAL between runs. Accepts 60, 30s, 5m, 1h, 1d.
                           Rate limits are absorbed internally; the loop
                           never crashes on a 403.
        --include-passwords adds the contextual + shape-based PlainTextPassword
                           patterns. High false-positive rate; review before
                           enabling auto_inform for that type.
        --max-rechecks N    re-checks at most N existing findings per run for
                           remediation status (default 100). --no-recheck off.
        --max-notices N     opens at most N issues per run, only on types where
                           auto_inform=true (default 25). --no-notify off.
        --max-per-provider N caps per-needle file fetches per pass (default 50).

        --out is a SQLite path; the sibling .htm report is regenerated
        each run from the full DB. The database is shared with the
        Python scraper (python/scraper.py) — both can run concurrently.

        Token (one of):
          GITHUB_TOKEN env var, or
          %APPDATA%\MindAttic\FractionsOfACent\settings.json
            with { "github_token": "github_pat_..." }
          Fine-grained PAT, public-repo read scope is enough.

        For elevated rate limits in academic studies, apply for GitHub
        Research Access (GitHub's Acceptable Use Policy). Do not rotate
        multiple PATs to evade limits — that is an AUP violation.
        """);
}
