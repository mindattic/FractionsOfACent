using FractionsOfACent;
using Microsoft.Extensions.Configuration;

var reportPath = "findings.htm";
var connectionString = Settings.ResolveConnectionString();
var maxPerProvider = 50;
var maxRechecks = 100;
var maxNotices = 25;
var includePasswords = false;
var loopIntervalSeconds = 0;
var providerFilter = new List<string>();
var verbose = false;
var headless = false;

for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--report":
            if (!TryNextString(args, ref i, out reportPath!)) return 2;
            break;
        case "--connection":
            if (!TryNextString(args, ref i, out connectionString!)) return 2;
            break;
        case "--max-per-provider":
            if (!TryNextInt(args, ref i, out maxPerProvider)) return 2;
            break;
        case "--max-rechecks":
            if (!TryNextInt(args, ref i, out maxRechecks)) return 2;
            break;
        case "--no-recheck":
            maxRechecks = 0;
            break;
        case "--max-notices":
            if (!TryNextInt(args, ref i, out maxNotices)) return 2;
            break;
        case "--no-notify":
            maxNotices = 0;
            break;
        case "--include-passwords":
            includePasswords = true;
            break;
        case "--loop":
            if (!TryNextDuration(args, ref i, out loopIntervalSeconds)) return 2;
            break;
        case "--provider":
            if (!TryNextString(args, ref i, out var providerName)) return 2;
            providerFilter.Add(providerName);
            break;
        case "-v":
        case "--verbose":
            verbose = true;
            break;
        case "--headless":
            headless = true;
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

// Build a minimal IConfiguration so CLI users can opt into User Secrets and
// %APPDATA%\MindAttic\GitHub\tokens.json the same way the Blazor host does.
var cliConfig = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
    .Add(new MindAttic.Vault.Configuration.MindAtticConfigurationSource())
    .AddUserSecrets<Program>(optional: true)
    .AddEnvironmentVariables()
    .Build();

var token = new GitHubTokenProvider(cliConfig).Get();
if (string.IsNullOrWhiteSpace(token))
{
    Console.Error.WriteLine("error: GitHub PAT not found. Set one of:");
    Console.Error.WriteLine("  dotnet user-secrets set \"MindAttic:Vault:Tokens:github\" \"github_pat_...\"");
    Console.Error.WriteLine("  GITHUB_TOKEN env var");
    Console.Error.WriteLine($"  legacy {{ \"github_token\": \"github_pat_...\" }} in {Settings.ConfigPath}");
    return 2;
}

if (verbose) Console.Error.WriteLine($"[config] report={reportPath} max={maxPerProvider}");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

using var client = new GitHubClient(token);
using var db = Db.CreateForCli(connectionString);
var scraper = new Scraper(
    client, db, new FileInfo(reportPath),
    maxPerProvider, maxRechecks, maxNotices, includePasswords);
var providerArr = providerFilter.Count > 0 ? providerFilter.ToArray() : null;

// Default cadence when no explicit --loop and we're in a long-lived mode
// (interactive menu or --headless). One-shot mode only kicks in for an
// explicit single-pass invocation, which we treat as: --headless without
// --loop. Interactive always loops so the menu remains useful.
var oneShot = headless && loopIntervalSeconds == 0;
if (!oneShot && loopIntervalSeconds == 0) loopIntervalSeconds = 60;

var scanLoop = oneShot
    ? scraper.RunAsync(providerArr, cts.Token).ContinueWith(_ => { }, TaskScheduler.Default)
    : RunLoopAsync(scraper, providerArr, loopIntervalSeconds, cts);

if (headless)
{
    await scanLoop;
}
else
{
    Console.Error.WriteLine($"[interactive] scanner running every {loopIntervalSeconds}s — press ? for menu");
    Menu.PrintStatus(db);
    var menuTask = Menu.RunAsync(db, cts);
    await Task.WhenAny(scanLoop, menuTask);
    cts.Cancel();
    try { await scanLoop; }
    catch (OperationCanceledException) { }
    catch (Exception ex) { Console.Error.WriteLine($"[shutdown] scan loop: {ex.Message}"); }
    try { await menuTask; }
    catch (OperationCanceledException) { }
    catch (Exception ex) { Console.Error.WriteLine($"[shutdown] menu: {ex.Message}"); }
}
return 0;

static async Task RunLoopAsync(Scraper scraper, string[]? providerArr,
    int loopIntervalSeconds, CancellationTokenSource cts)
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
            // Scraper absorbs rate-limit and HTTP errors internally; this
            // catches genuinely unexpected exceptions (DB locked, OOM).
            // Log and keep looping — indefinite operation is the contract.
            Console.Error.WriteLine($"[loop] pass failed: {e.Message}");
        }
        if (cts.IsCancellationRequested) break;
        Console.Error.WriteLine($"[loop] sleeping {loopIntervalSeconds}s");
        try { await Task.Delay(TimeSpan.FromSeconds(loopIntervalSeconds), cts.Token); }
        catch (OperationCanceledException) { break; }
    }
}

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

static bool TryNextString(string[] args, ref int i, out string value)
{
    if (i + 1 >= args.Length)
    {
        Console.Error.WriteLine($"error: {args[i]} requires a value");
        value = "";
        return false;
    }
    value = args[++i];
    return true;
}

static bool TryNextInt(string[] args, ref int i, out int value)
{
    if (!TryNextString(args, ref i, out var s)) { value = 0; return false; }
    if (!int.TryParse(s, out value))
    {
        Console.Error.WriteLine($"error: {args[i - 1]} expected an integer, got '{s}'");
        return false;
    }
    return true;
}

static bool TryNextDuration(string[] args, ref int i, out int seconds)
{
    if (!TryNextString(args, ref i, out var s)) { seconds = 0; return false; }
    try { seconds = ParseDuration(s); return true; }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"error: {args[i - 1]} {ex.Message}");
        seconds = 0;
        return false;
    }
}

static void PrintHelp()
{
    Console.WriteLine("""
        fractions — leaked-credential prevalence scanner (metadata only)

        Usage:
          fractions [--report findings.htm] [--connection "<conn-string>"]
                    [--headless]
                    [--max-per-provider N]
                    [--max-rechecks N | --no-recheck]
                    [--max-notices N  | --no-notify]
                    [--include-passwords]
                    [--loop INTERVAL]
                    [--provider anthropic] [--provider github-pat-classic ...]
                    [-v]

        Modes:
          (default)  Interactive — scanner loops in the background; an
                     in-terminal menu accepts [p]ause, [r]esume, [s]tatus,
                     [q]uit. Pause/resume go through the same DB flag the
                     Blazor Settings tab uses.
          --headless No menu. Runs the loop (or a single pass if --loop
                     is omitted) and obeys ScannerControl.RequestedState.
                     Use this when launching as a Blazor sidecar.

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

        Persistence is SQL Server LocalDB (FractionsOfACent database) by
        default; --connection overrides for any other SQL Server instance,
        as does the FRACTIONS_DB env var. The Blazor app reads from the
        same database; both can run concurrently. The .htm report is
        regenerated each pass from the full DB.

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
