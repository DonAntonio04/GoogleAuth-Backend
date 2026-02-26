using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GoogleAuth_Backend.Migrations
{
    /// <inheritdoc />
    public partial class AgregarCampoTokenHash : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Solo le decimos que agregue la columna nueva a la tabla que ya existe
            migrationBuilder.AddColumn<string>(
                name: "TokenHash",
                table: "Usuarios",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "TokenHash",
                table: "Usuarios");
        }
    }
}
