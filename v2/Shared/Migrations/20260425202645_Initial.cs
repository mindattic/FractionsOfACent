using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FractionsOfACent.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ExposureTypes",
                columns: table => new
                {
                    Name = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    AutoInform = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExposureTypes", x => x.Name);
                });

            migrationBuilder.CreateTable(
                name: "Notices",
                columns: table => new
                {
                    KeySha256 = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    RepoFullName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    FilePath = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    Channel = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    IssueNumber = table.Column<int>(type: "int", nullable: true),
                    IssueHtmlUrl = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    SentAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Status = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Error = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Notices", x => new { x.KeySha256, x.RepoFullName, x.FilePath, x.Channel });
                });

            migrationBuilder.CreateTable(
                name: "RemediationChecks",
                columns: table => new
                {
                    KeySha256 = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    RepoFullName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    FilePath = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    CheckedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Status = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    CommitSha = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RemediationChecks", x => new { x.KeySha256, x.RepoFullName, x.FilePath, x.CheckedAtUtc });
                });

            migrationBuilder.CreateTable(
                name: "ScannedFiles",
                columns: table => new
                {
                    RepoFullName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    FilePath = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    CommitSha = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    ScannedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScannedFiles", x => new { x.RepoFullName, x.FilePath });
                });

            migrationBuilder.CreateTable(
                name: "Findings",
                columns: table => new
                {
                    KeySha256 = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    RepoFullName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    FilePath = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    Provider = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ExposureType = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false, defaultValue: "ApiKey"),
                    ModelHint = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    RepoUrl = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: true),
                    RepoHtmlUrl = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: true),
                    AuthorLogin = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    FileHtmlUrl = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    CommitSha = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    DefaultBranch = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    KeyPrefix = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                    KeyLength = table.Column<int>(type: "int", nullable: false),
                    FirstSeenUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Findings", x => new { x.KeySha256, x.RepoFullName, x.FilePath });
                    table.ForeignKey(
                        name: "FK_Findings_ExposureTypes_ExposureType",
                        column: x => x.ExposureType,
                        principalTable: "ExposureTypes",
                        principalColumn: "Name",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Findings_Author",
                table: "Findings",
                column: "AuthorLogin");

            migrationBuilder.CreateIndex(
                name: "IX_Findings_ExposureType",
                table: "Findings",
                column: "ExposureType");

            migrationBuilder.CreateIndex(
                name: "IX_Findings_Provider",
                table: "Findings",
                column: "Provider");

            migrationBuilder.CreateIndex(
                name: "IX_Findings_Repo",
                table: "Findings",
                column: "RepoFullName");

            migrationBuilder.CreateIndex(
                name: "IX_Notices_Repo",
                table: "Notices",
                column: "RepoFullName");

            migrationBuilder.CreateIndex(
                name: "IX_RemediationChecks_Finding",
                table: "RemediationChecks",
                columns: new[] { "KeySha256", "RepoFullName", "FilePath" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Findings");

            migrationBuilder.DropTable(
                name: "Notices");

            migrationBuilder.DropTable(
                name: "RemediationChecks");

            migrationBuilder.DropTable(
                name: "ScannedFiles");

            migrationBuilder.DropTable(
                name: "ExposureTypes");
        }
    }
}
