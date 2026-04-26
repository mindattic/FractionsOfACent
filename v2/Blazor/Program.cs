using FractionsOfACent;
using FractionsOfACent.Blazor.Components;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var connectionString =
    builder.Configuration.GetConnectionString("Fractions")
    ?? Settings.ResolveConnectionString();

builder.Services.AddDbContextFactory<FractionsContext>(opts =>
    opts.UseSqlServer(connectionString));

// Db wraps the context factory; scoped matches Blazor Server's per-circuit
// lifetime but the underlying factory is a singleton.
builder.Services.AddScoped<Db>(sp =>
    new Db(sp.GetRequiredService<IDbContextFactory<FractionsContext>>()));

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

// Apply migrations + seed exposure types on host start. Idempotent: if
// the CLI scraper already created the schema, this is a fast no-op.
Db.EnsureCreatedAndSeeded(
    app.Services.GetRequiredService<IDbContextFactory<FractionsContext>>());

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
