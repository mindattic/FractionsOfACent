using System.Text.RegularExpressions;

namespace FractionsOfAPenny;

public sealed record ProviderPattern(
    string Provider,
    Regex Regex,
    string SearchNeedle,
    string[] ModelHints);

public static class Patterns
{
    public static readonly ProviderPattern[] All =
    [
        new ProviderPattern(
            Provider: "anthropic",
            Regex: new Regex(@"sk-ant-api03-[A-Za-z0-9\-_]{93}AA", RegexOptions.Compiled),
            SearchNeedle: "sk-ant-api03-",
            ModelHints:
            [
                "claude-opus-4",
                "claude-sonnet-4",
                "claude-haiku-4",
                "claude-3-7-sonnet",
                "claude-3-5-sonnet",
                "claude-3-5-haiku",
                "claude-3-opus",
                "claude-3-sonnet",
                "claude-3-haiku",
            ]),
        new ProviderPattern(
            Provider: "openai",
            Regex: new Regex(@"sk-proj-[A-Za-z0-9\-_]{40,200}", RegexOptions.Compiled),
            SearchNeedle: "sk-proj-",
            ModelHints:
            [
                "gpt-4o",
                "gpt-4-turbo",
                "gpt-4",
                "gpt-3.5-turbo",
                "o1-preview",
                "o1-mini",
                "o3-mini",
            ]),
        new ProviderPattern(
            Provider: "openai-legacy",
            Regex: new Regex(@"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{48}(?![A-Za-z0-9])", RegexOptions.Compiled),
            SearchNeedle: "\"sk-\"",
            ModelHints:
            [
                "gpt-4",
                "gpt-3.5-turbo",
                "text-davinci-003",
            ]),
        new ProviderPattern(
            Provider: "google-gemini",
            Regex: new Regex(@"AIza[A-Za-z0-9\-_]{35}", RegexOptions.Compiled),
            SearchNeedle: "AIza",
            ModelHints:
            [
                "gemini-2.0-flash",
                "gemini-1.5-pro",
                "gemini-1.5-flash",
                "gemini-pro",
                "gemini-ultra",
            ]),
    ];

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
