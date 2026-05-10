using Microsoft.Extensions.Configuration;
using MindAttic.Vault.Credentials;

namespace FractionsOfACent;

/// <summary>
/// Resolves the GitHub PAT used by <see cref="GitHubClient"/>. Walks four
/// sources in priority order:
/// <list type="number">
///   <item><description><c>IConfiguration["MindAttic:Vault:Tokens:github"]</c> — User Secrets,
///         App Service Application Settings, or Azure Key Vault (cloud-native).</description></item>
///   <item><description><c>TokenStore.ForBucket("GitHub").Get("github")</c> — new canonical
///         <c>%APPDATA%\MindAttic\GitHub\tokens.json</c> file.</description></item>
///   <item><description><c>GITHUB_TOKEN</c> environment variable — legacy convention.</description></item>
///   <item><description><see cref="Settings.LoadGitHubToken"/> — legacy
///         <c>%APPDATA%\MindAttic\FractionsOfACent\settings.json</c>; will be removed in a
///         future release once existing developer machines have migrated.</description></item>
/// </list>
/// Returns <c>null</c> when no source has a non-empty token. Callers that require
/// a token must throw their own descriptive error when this returns null.
/// </summary>
public sealed class GitHubTokenProvider
{
    private readonly IConfiguration config;

    public GitHubTokenProvider(IConfiguration config)
    {
        this.config = config ?? throw new ArgumentNullException(nameof(config));
    }

    public string? Get()
    {
        var fromConfig = config["MindAttic:Vault:Tokens:github"];
        if (!string.IsNullOrWhiteSpace(fromConfig)) return fromConfig.Trim();

        var fromTokenStore = TokenStore.ForBucket("GitHub").Get("github");
        if (!string.IsNullOrWhiteSpace(fromTokenStore)) return fromTokenStore;

        var fromEnv = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv;

#pragma warning disable CS0618 // intentional: legacy fallback while users migrate
        return Settings.LoadGitHubToken();
#pragma warning restore CS0618
    }
}
