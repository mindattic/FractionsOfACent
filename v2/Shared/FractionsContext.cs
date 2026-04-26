using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace FractionsOfACent;

/// <summary>
/// EF Core context backed by SQL Server LocalDB. The CLI scraper writes
/// continuously; the Blazor UI reads. Composite keys mirror the original
/// SQLite schema so dedup behavior is identical.
/// </summary>
public class FractionsContext : DbContext
{
    public DbSet<FindingEntity> Findings => Set<FindingEntity>();
    public DbSet<ScannedFileEntity> ScannedFiles => Set<ScannedFileEntity>();
    public DbSet<NoticeEntity> Notices => Set<NoticeEntity>();
    public DbSet<RemediationCheckEntity> RemediationChecks => Set<RemediationCheckEntity>();
    public DbSet<ExposureTypeEntity> ExposureTypes => Set<ExposureTypeEntity>();
    public DbSet<ScannerControlEntity> ScannerControls => Set<ScannerControlEntity>();

    public FractionsContext(DbContextOptions<FractionsContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder mb)
    {
        mb.Entity<ExposureTypeEntity>(b =>
        {
            b.ToTable("ExposureTypes");
            b.HasKey(e => e.Name);
            b.Property(e => e.Name).HasMaxLength(64);
            b.Property(e => e.Description).HasMaxLength(512);
            b.Property(e => e.AutoInform).HasDefaultValue(false);
        });

        mb.Entity<FindingEntity>(b =>
        {
            b.ToTable("Findings");
            b.HasKey(e => new { e.KeySha256, e.RepoFullName, e.FilePath });
            b.Property(e => e.KeySha256).HasMaxLength(64);
            b.Property(e => e.RepoFullName).HasMaxLength(256);
            b.Property(e => e.FilePath).HasMaxLength(1024);
            b.Property(e => e.Provider).HasMaxLength(64);
            b.Property(e => e.ExposureType).HasMaxLength(64).HasDefaultValue("ApiKey");
            b.Property(e => e.ModelHint).HasMaxLength(64);
            b.Property(e => e.RepoUrl).HasMaxLength(1024);
            b.Property(e => e.RepoHtmlUrl).HasMaxLength(1024);
            b.Property(e => e.AuthorLogin).HasMaxLength(128);
            b.Property(e => e.FileHtmlUrl).HasMaxLength(2048);
            b.Property(e => e.CommitSha).HasMaxLength(64);
            b.Property(e => e.DefaultBranch).HasMaxLength(128);
            b.Property(e => e.KeyPrefix).HasMaxLength(32);

            b.HasOne(e => e.ExposureTypeNav)
                .WithMany()
                .HasForeignKey(e => e.ExposureType)
                .HasPrincipalKey(et => et.Name)
                .OnDelete(DeleteBehavior.Restrict);

            b.HasIndex(e => e.ExposureType).HasDatabaseName("IX_Findings_ExposureType");
            b.HasIndex(e => e.Provider).HasDatabaseName("IX_Findings_Provider");
            b.HasIndex(e => e.RepoFullName).HasDatabaseName("IX_Findings_Repo");
            b.HasIndex(e => e.AuthorLogin).HasDatabaseName("IX_Findings_Author");
        });

        mb.Entity<ScannedFileEntity>(b =>
        {
            b.ToTable("ScannedFiles");
            b.HasKey(e => new { e.RepoFullName, e.FilePath });
            b.Property(e => e.RepoFullName).HasMaxLength(256);
            b.Property(e => e.FilePath).HasMaxLength(1024);
            b.Property(e => e.CommitSha).HasMaxLength(64);
        });

        mb.Entity<NoticeEntity>(b =>
        {
            b.ToTable("Notices");
            b.HasKey(e => new { e.KeySha256, e.RepoFullName, e.FilePath, e.Channel });
            b.Property(e => e.KeySha256).HasMaxLength(64);
            b.Property(e => e.RepoFullName).HasMaxLength(256);
            b.Property(e => e.FilePath).HasMaxLength(1024);
            b.Property(e => e.Channel).HasMaxLength(64);
            b.Property(e => e.IssueHtmlUrl).HasMaxLength(2048);
            b.Property(e => e.Status).HasMaxLength(32);
            b.HasIndex(e => e.RepoFullName).HasDatabaseName("IX_Notices_Repo");
        });

        mb.Entity<ScannerControlEntity>(b =>
        {
            b.ToTable("ScannerControl");
            b.HasKey(e => e.Id);
            // Single-row table; we always write Id=1 explicitly.
            b.Property(e => e.Id).ValueGeneratedNever();
            b.Property(e => e.RequestedState).HasMaxLength(16);
            b.Property(e => e.CurrentLabel).HasMaxLength(128);
        });

        mb.Entity<RemediationCheckEntity>(b =>
        {
            b.ToTable("RemediationChecks");
            b.HasKey(e => new { e.KeySha256, e.RepoFullName, e.FilePath, e.CheckedAtUtc });
            b.Property(e => e.KeySha256).HasMaxLength(64);
            b.Property(e => e.RepoFullName).HasMaxLength(256);
            b.Property(e => e.FilePath).HasMaxLength(1024);
            b.Property(e => e.Status).HasMaxLength(32);
            b.Property(e => e.CommitSha).HasMaxLength(64);
            b.HasIndex(e => new { e.KeySha256, e.RepoFullName, e.FilePath })
                .HasDatabaseName("IX_RemediationChecks_Finding");
        });
    }
}

/// <summary>
/// Lets `dotnet ef` build the context against the default LocalDB
/// connection without needing the Web project's host. Production code
/// uses AddDbContext / AddDbContextFactory with the appsettings string.
/// </summary>
public class FractionsContextDesignFactory : IDesignTimeDbContextFactory<FractionsContext>
{
    public FractionsContext CreateDbContext(string[] args)
    {
        var opts = new DbContextOptionsBuilder<FractionsContext>()
            .UseSqlServer(Settings.DefaultConnectionString)
            .Options;
        return new FractionsContext(opts);
    }
}
