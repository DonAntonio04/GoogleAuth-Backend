using System.Text.Json.Serialization;

namespace GoogleAuth_Backend.Models
{
    public class RegisterRequest
    {
        public string Nombre { get; set; } = string.Empty;

     
        public string ApellidoPaterno { get; set; } = string.Empty;
        public string ApellidoMaterno { get; set; } = string.Empty;

        [JsonPropertyName("Email")]
        public string Correo { get; set; } = string.Empty;

        public string Telefono { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string DeviceId { get; set; } = string.Empty; // DeviceId agregado/confirmado
    }
}