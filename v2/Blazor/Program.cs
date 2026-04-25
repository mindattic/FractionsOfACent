using FractionsOfACent;
using FractionsOfACent.Blazor.Components;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Each circuit gets its own SQLite connection (cheap with WAL). Scoped
// matches Blazor Server's per-circuit lifetime.
builder.Services.AddScoped<Db>(sp =>
{
    var cfg = sp.GetRequiredService<IConfiguration>();
    var path = cfg["FractionsOfACent:DbPath"] ?? "findings.db";
    return new Db(new FileInfo(Path.GetFullPath(path)));
});

// Singleton: the GitHub HTTP client is cheap to share, and the token
// resolution only needs to happen once per process.
builder.Services.AddSingleton<GitHubClient>(_ =>
{
    var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN")
        ?? Settings.LoadGitHubToken()
        ?? throw new InvalidOperationException(
            "GITHUB_TOKEN env var or settings.json is required to send notices.");
    return new GitHubClient(token);
});

builder.Services.AddSingleton<NoticeConfig>(sp =>
{
    var cfg = sp.GetRequiredService<IConfiguration>();
    var section = cfg.GetSection("FractionsOfACent");
    var def = NoticeConfig.Default;
    return new NoticeConfig(
        Channel: section["NoticeChannel"] ?? def.Channel,
        Title: section["NoticeTitle"] ?? def.Title,
        Body: section["NoticeBody"] ?? def.Body);
});

builder.Services.AddScoped<NoticeService>(sp => new NoticeService(
    sp.GetRequiredService<Db>(),
    sp.GetRequiredService<GitHubClient>(),
    sp.GetRequiredService<NoticeConfig>()));

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
