using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace GoogleAuth.Models
{
    public class UsuarioSimulado
    {
        public string Id { get; set; }
        public string Nombre { get; set; } = string.Empty;
        public string Apellido { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        // Nullable porque son opcionales y pueden venir NULL desde la BD
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
        public string Apellido { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        // Nullable porque el usuario puede no enviarlos
        public string? Telefono { get; set; } = null;
        public string? DeviceId { get; set; } = null;
    }

    public class GoogleRequest
    {
        public string IdToken { get; set; } = string.Empty;
    }
}