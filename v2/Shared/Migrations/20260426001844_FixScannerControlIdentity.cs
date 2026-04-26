using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FractionsOfACent.Migrations
{
    /// <inheritdoc />
    public partial class FixScannerControlIdentity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // SQL Server cannot ALTER a column to remove IDENTITY in place.
            // Drop and recreate via raw SQL — table is brand-new and empty.
            migrationBuilder.Sql("DROP TABLE [ScannerControl];");
            migrationBuilder.Sql(@"
                CREATE TABLE [ScannerControl] (
                    [Id] int NOT NULL,
                    [RequestedState] nvarchar(16) NOT NULL,
                    [RequestedAtUtc] datetime2 NOT NULL,
                    [LastHeartbeatUtc] datetime2 NULL,
                    [CurrentLabel] nvarchar(128) NULL,
                    CONSTRAINT [PK_ScannerControl] PRIMARY KEY ([Id])
                );");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP TABLE [ScannerControl];");
            migrationBuilder.Sql(@"
                CREATE TABLE [ScannerControl] (
                    [Id] int IDENTITY(1,1) NOT NULL,
                    [RequestedState] nvarchar(16) NOT NULL,
                    [RequestedAtUtc] datetime2 NOT NULL,
                    [LastHeartbeatUtc] datetime2 NULL,
                    [CurrentLabel] nvarchar(128) NULL,
                    CONSTRAINT [PK_ScannerControl] PRIMARY KEY ([Id])
                );");
        }
    }
}
