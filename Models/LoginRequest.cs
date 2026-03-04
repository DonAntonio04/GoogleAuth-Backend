using System.Text.Json.Serialization; // <-- Agrega este using arriba

namespace GoogleAuth_Backend.Models
{
    public class LoginRequest
    {
        // Esto le dice al deserializador: "Busca la propiedad 'Email' en el JSON y guárdala aquí"
        [JsonPropertyName("Email")]
        public string Correo { get; set; }

        public string Password { get; set; }
    }

    public class LogoutRequest
    {
        public string Token { get; set; }
    }
}