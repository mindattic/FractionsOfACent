using System.Text.Json;
using System.Text.Json.Serialization;

namespace FractionsOfAPenny;

public static class Settings
{
    public static string ConfigPath
    {
        get
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return Path.Combine(appData, "MindAttic", "FractionsOfAPenny", "settings.json");
        }
    }

    public static string? LoadGitHubToken()
    {
        var path = ConfigPath;
        if (!File.Exists(path)) return null;
        try
        {
            using var stream = File.OpenRead(path);
            var doc = JsonSerializer.Deserialize<SettingsFile>(stream);
            return string.IsNullOrWhiteSpace(doc?.GitHubToken) ? null : doc.GitHubToken;
        }
        catch
        {
            return null;
        }
    }

    private sealed class SettingsFile
    {
        [JsonPropertyName("github_token")] public string? GitHubToken { get; set; }
    }
}
