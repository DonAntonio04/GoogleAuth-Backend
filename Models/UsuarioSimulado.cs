using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace GoogleAuth.Models
{
    public class UsuarioSimulado
    {
  
        public int Id { get; set; }

        [Column("Nombres")]
        public string Nombre { get; set; } = string.Empty;

        public string ApellidoPaterno { get; set; } = string.Empty;
        public string ApellidoMaterno { get; set; } = string.Empty;

        public string Correo { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        public string? Telefono { get; set; } = null;
        public string? DeviceId { get; set; } = null; 
        public string? TokenHash { get; set; } = null;
    }

    public class ReciboSeguro
    {
        public string Data { get; set; } = string.Empty;
    }

    public class RegisterRequest
    {
        public string Nombre { get; set; } = string.Empty;

        public string ApellidoPaterno { get; set; } = string.Empty;
        public string ApellidoMaterno { get; set; } = string.Empty;

        [JsonPropertyName("Email")]
        public string Correo { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;

        public string? Telefono { get; set; } = null;
        public string? DeviceId { get; set; } = null;
    }

    public class GoogleRequest
    {
        public string IdToken { get; set; } = string.Empty;
    }
}