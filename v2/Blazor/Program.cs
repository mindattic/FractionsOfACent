using FractionsOfACent;
using FractionsOfACent.Blazor.Components;
using Microsoft.EntityFrameworkCore;
using MindAttic.Vault.Configuration;
using MindAttic.Vault.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// Cloud-native configuration chain. Lower sources first; later sources win.
//   AddJsonFile  — non-secret defaults (already present via WebApplicationBuilder).
//   AddMindAtticVaultFiles — legacy %APPDATA%\MindAttic\<bucket> on dev machines.
//   AddUserSecrets — dev secrets shared family-wide via mindattic-vault-shared id.
//   AddEnvironmentVariables — App Service Application Settings + Key Vault refs in prod.
builder.Configuration
    .AddMindAtticVaultFiles()
    .AddUserSecrets<Program>(optional: true)
    .AddEnvironmentVariables();

builder.Services.AddMindAtticVault(builder.Configuration);
builder.Services.AddSingleton<GitHubTokenProvider>();

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
builder.Services.AddSingleton<GitHubClient>(sp =>
{
    var token = sp.GetRequiredService<GitHubTokenProvider>().Get()
        ?? throw new InvalidOperationException(
            "GitHub token is required. Set it via " +
            "`dotnet user-secrets set \"MindAttic:Vault:Tokens:github\" \"ghp_...\"` " +
            "(dev), the GITHUB_TOKEN env var (legacy), or as the App Service " +
            "Application Setting MindAttic__Vault__Tokens__github (prod).");
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
