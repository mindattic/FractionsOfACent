using FractionsOfAPenny;

var outPath = "findings.json";
var maxPerProvider = 50;
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
var scraper = new Scraper(client, new FileInfo(outPath), maxPerProvider);
await scraper.RunAsync(
    providerFilter.Count > 0 ? providerFilter.ToArray() : null,
    cts.Token);
return 0;

static void PrintHelp()
{
    Console.WriteLine("""
        fractions — leaked-credential prevalence scanner (metadata only)

        Usage:
          fractions [--out findings.json] [--max-per-provider N]
                    [--provider anthropic] [--provider openai] [-v]

        Token (one of):
          GITHUB_TOKEN env var, or
          %APPDATA%\MindAttic\FractionsOfAPenny\settings.json
            with { "github_token": "github_pat_..." }
          Fine-grained PAT, public-repo read scope is enough.

        Providers: anthropic, openai, openai-legacy, google-gemini
        """);
}
