using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FractionsOfACent.Migrations
{
    /// <inheritdoc />
    public partial class AddScannerControl : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ScannerControl",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    RequestedState = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    RequestedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    LastHeartbeatUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CurrentLabel = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScannerControl", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ScannerControl");
        }
    }
}
