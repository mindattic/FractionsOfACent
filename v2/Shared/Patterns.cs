using System.Text.RegularExpressions;

namespace FractionsOfACent;

/// <summary>
/// One detection rule. Provider is the specific source (e.g. 'aws',
/// 'anthropic', 'postgres'); ExposureType is the broad category that
/// drives notice templating, filtering, and reporting in the Web UI.
/// </summary>
public sealed record ProviderPattern(
    string Provider,
    string ExposureType,
    Regex Regex,
    string SearchNeedle,
    string[] ModelHints);

/// <summary>
/// Stable list of exposure category names. Mirrored as rows in the
/// exposure_types SQLite table; the foreign key on findings points here.
/// </summary>
public static class ExposureTypes
{
    public const string ApiKey = "ApiKey";
    public const string ConnectionString = "ConnectionString";
    public const string PrivateKey = "PrivateKey";
    public const string PlainTextPassword = "PlainTextPassword";

    public static readonly (string Name, string Description)[] All =
    [
        (ApiKey,
            "Provider-issued API token (LLM, cloud, payments, communications, package registries, version control)."),
        (ConnectionString,
            "Database / cache / message-broker URI containing inline username:password credentials."),
        (PrivateKey,
            "PEM-encoded private key block (RSA, DSA, EC, OpenSSH, PGP)."),
        (PlainTextPassword,
            "Variable assignment to a string literal under a name like 'password', 'passwd', 'secret', or 'pwd'. High false-positive rate; opt-in scan only."),
    ];
}

public static class Patterns
{
    /// <summary>
    /// Default scan set. PlainTextPassword patterns are NOT included here
    /// — opt-in via Patterns.WithPasswords() because their signal-to-noise
    /// is too poor to justify auto-opening issues against arbitrary repos.
    /// </summary>
    public static readonly ProviderPattern[] All =
    [
        // --- LLM API keys -----------------------------------------------
        new(
            Provider: "anthropic",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"sk-ant-api03-[A-Za-z0-9\-_]{93}AA", RegexOptions.Compiled),
            SearchNeedle: "sk-ant-api03-",
            ModelHints:
            [
                "claude-opus-4", "claude-sonnet-4", "claude-haiku-4",
                "claude-3-7-sonnet", "claude-3-5-sonnet", "claude-3-5-haiku",
                "claude-3-opus", "claude-3-sonnet", "claude-3-haiku",
            ]),
        new(
            Provider: "openai",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"sk-proj-[A-Za-z0-9\-_]{40,200}", RegexOptions.Compiled),
            SearchNeedle: "sk-proj-",
            ModelHints:
            [
                "gpt-4o", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo",
                "o1-preview", "o1-mini", "o3-mini",
            ]),
        new(
            Provider: "openai-legacy",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{48}(?![A-Za-z0-9])", RegexOptions.Compiled),
            SearchNeedle: "\"sk-\"",
            ModelHints: ["gpt-4", "gpt-3.5-turbo", "text-davinci-003"]),
        new(
            Provider: "google-gemini",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"AIza[A-Za-z0-9\-_]{35}", RegexOptions.Compiled),
            SearchNeedle: "AIza",
            ModelHints:
            [
                "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash",
                "gemini-pro", "gemini-ultra",
            ]),

        // --- Cloud + infrastructure ------------------------------------
        new(
            Provider: "aws-access-key",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])", RegexOptions.Compiled),
            SearchNeedle: "AKIA",
            ModelHints: []),
        new(
            Provider: "digitalocean-pat",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"dop_v1_[a-f0-9]{64}", RegexOptions.Compiled),
            SearchNeedle: "dop_v1_",
            ModelHints: []),
        new(
            Provider: "digitalocean-oauth",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"doo_v1_[a-f0-9]{64}", RegexOptions.Compiled),
            SearchNeedle: "doo_v1_",
            ModelHints: []),

        // --- Version control + package registries ----------------------
        new(
            Provider: "github-pat-classic",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"ghp_[A-Za-z0-9]{36}", RegexOptions.Compiled),
            SearchNeedle: "ghp_",
            ModelHints: []),
        new(
            Provider: "github-pat-fine",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"github_pat_[A-Za-z0-9_]{82}", RegexOptions.Compiled),
            SearchNeedle: "github_pat_",
            ModelHints: []),
        new(
            Provider: "github-oauth",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"gho_[A-Za-z0-9]{36}", RegexOptions.Compiled),
            SearchNeedle: "gho_",
            ModelHints: []),
        new(
            Provider: "github-app-user",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"ghu_[A-Za-z0-9]{36}", RegexOptions.Compiled),
            SearchNeedle: "ghu_",
            ModelHints: []),
        new(
            Provider: "github-app-server",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"ghs_[A-Za-z0-9]{36}", RegexOptions.Compiled),
            SearchNeedle: "ghs_",
            ModelHints: []),
        new(
            Provider: "npm-token",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"npm_[A-Za-z0-9]{36}", RegexOptions.Compiled),
            SearchNeedle: "npm_",
            ModelHints: []),
        new(
            Provider: "pypi-token",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}", RegexOptions.Compiled),
            SearchNeedle: "pypi-AgEIcHlwaS5vcmc",
            ModelHints: []),

        // --- Payments + commerce ---------------------------------------
        new(
            Provider: "stripe-secret-live",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"sk_live_[A-Za-z0-9]{24,99}", RegexOptions.Compiled),
            SearchNeedle: "sk_live_",
            ModelHints: []),
        new(
            Provider: "stripe-restricted-live",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"rk_live_[A-Za-z0-9]{24,99}", RegexOptions.Compiled),
            SearchNeedle: "rk_live_",
            ModelHints: []),
        new(
            Provider: "shopify-private",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"shppa_[a-fA-F0-9]{32}", RegexOptions.Compiled),
            SearchNeedle: "shppa_",
            ModelHints: []),
        new(
            Provider: "shopify-access",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"shpat_[a-fA-F0-9]{32}", RegexOptions.Compiled),
            SearchNeedle: "shpat_",
            ModelHints: []),
        new(
            Provider: "square-access",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"sq0atp-[A-Za-z0-9_-]{22}", RegexOptions.Compiled),
            SearchNeedle: "sq0atp-",
            ModelHints: []),
        new(
            Provider: "square-secret",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"sq0csp-[A-Za-z0-9_-]{43}", RegexOptions.Compiled),
            SearchNeedle: "sq0csp-",
            ModelHints: []),

        // --- Communications --------------------------------------------
        new(
            Provider: "slack-bot",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,40}", RegexOptions.Compiled),
            SearchNeedle: "xoxb-",
            ModelHints: []),
        new(
            Provider: "slack-user",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,40}", RegexOptions.Compiled),
            SearchNeedle: "xoxp-",
            ModelHints: []),
        new(
            Provider: "slack-webhook",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}", RegexOptions.Compiled),
            SearchNeedle: "hooks.slack.com/services",
            ModelHints: []),
        new(
            Provider: "discord-webhook",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"https://discord(?:app)?\.com/api/webhooks/\d{17,19}/[A-Za-z0-9_-]{60,}", RegexOptions.Compiled),
            SearchNeedle: "discord.com/api/webhooks",
            ModelHints: []),
        new(
            Provider: "sendgrid",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", RegexOptions.Compiled),
            SearchNeedle: "SG.",
            ModelHints: []),
        new(
            Provider: "mailgun",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"key-[a-f0-9]{32}", RegexOptions.Compiled),
            SearchNeedle: "key-",
            ModelHints: []),
        new(
            Provider: "twilio-sk",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"(?<![A-Za-z0-9])SK[a-f0-9]{32}(?![a-f0-9])", RegexOptions.Compiled),
            SearchNeedle: "SK",
            ModelHints: []),

        // --- Auth tokens ------------------------------------------------
        new(
            Provider: "jwt",
            ExposureType: ExposureTypes.ApiKey,
            Regex: new Regex(@"eyJ[A-Za-z0-9_=-]{10,}\.eyJ[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=-]{10,}", RegexOptions.Compiled),
            SearchNeedle: "eyJ",
            ModelHints: []),

        // --- Database / cache connection strings -----------------------
        new(
            Provider: "postgres-uri",
            ExposureType: ExposureTypes.ConnectionString,
            Regex: new Regex(@"postgres(?:ql)?://[^:\s'""@]+:[^@\s'""]{4,}@[^/\s'""]+(?:/[^\s'""<>]*)?", RegexOptions.Compiled),
            SearchNeedle: "postgres://",
            ModelHints: []),
        new(
            Provider: "mysql-uri",
            ExposureType: ExposureTypes.ConnectionString,
            Regex: new Regex(@"mysql://[^:\s'""@]+:[^@\s'""]{4,}@[^/\s'""]+(?:/[^\s'""<>]*)?", RegexOptions.Compiled),
            SearchNeedle: "mysql://",
            ModelHints: []),
        new(
            Provider: "mongodb-uri",
            ExposureType: ExposureTypes.ConnectionString,
            Regex: new Regex(@"mongodb(?:\+srv)?://[^:\s'""@]+:[^@\s'""]{4,}@[^/\s'""]+(?:/[^\s'""<>]*)?", RegexOptions.Compiled),
            SearchNeedle: "mongodb://",
            ModelHints: []),
        new(
            Provider: "redis-uri",
            ExposureType: ExposureTypes.ConnectionString,
            Regex: new Regex(@"rediss?://[^:\s'""@]+:[^@\s'""]{4,}@[^/\s'""]+(?:/[^\s'""<>]*)?", RegexOptions.Compiled),
            SearchNeedle: "redis://",
            ModelHints: []),

        // --- PEM private key blocks ------------------------------------
        new(
            Provider: "private-key-rsa",
            ExposureType: ExposureTypes.PrivateKey,
            Regex: new Regex(@"-----BEGIN RSA PRIVATE KEY-----[A-Za-z0-9+/=\s]{20,}-----END RSA PRIVATE KEY-----",
                RegexOptions.Compiled | RegexOptions.Singleline),
            SearchNeedle: "BEGIN RSA PRIVATE KEY",
            ModelHints: []),
        new(
            Provider: "private-key-openssh",
            ExposureType: ExposureTypes.PrivateKey,
            Regex: new Regex(@"-----BEGIN OPENSSH PRIVATE KEY-----[A-Za-z0-9+/=\s]{20,}-----END OPENSSH PRIVATE KEY-----",
                RegexOptions.Compiled | RegexOptions.Singleline),
            SearchNeedle: "BEGIN OPENSSH PRIVATE KEY",
            ModelHints: []),
        new(
            Provider: "private-key-ec",
            ExposureType: ExposureTypes.PrivateKey,
            Regex: new Regex(@"-----BEGIN EC PRIVATE KEY-----[A-Za-z0-9+/=\s]{20,}-----END EC PRIVATE KEY-----",
                RegexOptions.Compiled | RegexOptions.Singleline),
            SearchNeedle: "BEGIN EC PRIVATE KEY",
            ModelHints: []),
        new(
            Provider: "private-key-pgp",
            ExposureType: ExposureTypes.PrivateKey,
            Regex: new Regex(@"-----BEGIN PGP PRIVATE KEY BLOCK-----[A-Za-z0-9+/=\s]{20,}-----END PGP PRIVATE KEY BLOCK-----",
                RegexOptions.Compiled | RegexOptions.Singleline),
            SearchNeedle: "BEGIN PGP PRIVATE KEY",
            ModelHints: []),
    ];

    /// <summary>
    /// Opt-in: the contextual plaintext-password matcher.
    ///
    /// Variable-length lookbehind matches the literal value following an
    /// assignment to password / passwd / pwd / secret with a string
    /// literal (6-128 chars, no whitespace or quotes inside). The signal
    /// is genuinely poor — examples, fixtures, env-template files, and
    /// tutorials all match — so this is NOT in the default set, and the
    /// auto-notify pipeline filters it out (see Scraper.SendPendingNoticesAsync).
    /// </summary>
    public static readonly ProviderPattern[] PasswordPatterns =
    [
        // Contextual: any string literal assigned to a password-named field.
        // Catches both common-shape ("Hello123") and random ("k$jR9!q@P")
        // passwords because it ignores the value's shape and trusts the
        // surrounding `password = "..."` context.
        new(
            Provider: "password-contextual",
            ExposureType: ExposureTypes.PlainTextPassword,
            Regex: new Regex(
                @"(?<=\b(?:password|passwd|pwd|secret|api_secret|apikey|api_key)\b\s*[:=]\s*[""'])[^""'\s]{6,128}(?=[""'])",
                RegexOptions.Compiled | RegexOptions.IgnoreCase),
            SearchNeedle: "\"password\":",
            ModelHints: []),

        // Shape-based: common human password constructions (word+number,
        // word+number+symbol, etc.). High false-positive rate even within
        // password-tagged files — catches "version1", "step2", "test99",
        // tutorial fixtures, etc. Useful only as an exploratory sweep
        // gated behind manual review (auto_inform=false). Same needle as
        // the contextual pattern so we run them on the same fetched files.
        new(
            Provider: "password-shape-word-num",
            ExposureType: ExposureTypes.PlainTextPassword,
            Regex: new Regex(
                @"(?<![A-Za-z0-9])[A-Z][a-z]{2,15}\d{1,5}(?![A-Za-z0-9])",
                RegexOptions.Compiled),
            SearchNeedle: "\"password\":",
            ModelHints: []),
        new(
            Provider: "password-shape-word-num-sym",
            ExposureType: ExposureTypes.PlainTextPassword,
            Regex: new Regex(
                @"(?<![A-Za-z0-9])[A-Z][a-z]{2,15}\d{1,5}[!@#$%^&*?_-](?![A-Za-z0-9!])",
                RegexOptions.Compiled),
            SearchNeedle: "\"password\":",
            ModelHints: []),
        new(
            Provider: "password-shape-word-word-num",
            ExposureType: ExposureTypes.PlainTextPassword,
            Regex: new Regex(
                @"(?<![A-Za-z0-9])[A-Z][a-z]{2,15}[A-Z][a-z]{2,15}\d{1,5}(?![A-Za-z0-9])",
                RegexOptions.Compiled),
            SearchNeedle: "\"password\":",
            ModelHints: []),
        new(
            Provider: "password-shape-word-word-num-sym",
            ExposureType: ExposureTypes.PlainTextPassword,
            Regex: new Regex(
                @"(?<![A-Za-z0-9])[A-Z][a-z]{2,15}[A-Z][a-z]{2,15}\d{1,5}[!@#$%^&*?_-](?![A-Za-z0-9!])",
                RegexOptions.Compiled),
            SearchNeedle: "\"password\":",
            ModelHints: []),
    ];

    public static ProviderPattern[] WithPasswords() =>
        All.Concat(PasswordPatterns).ToArray();

    public static string? InferModel(string contextWindow, string[] hints)
    {
        foreach (var hint in hints)
        {
            if (contextWindow.Contains(hint, StringComparison.OrdinalIgnoreCase))
            {
                return hint;
            }
        }
        return null;
    }
}
