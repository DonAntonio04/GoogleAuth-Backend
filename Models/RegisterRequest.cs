namespace GoogleAuth_Backend.Models
{
    public class RegisterRequest
    {
        public string Nombre { get; set; } = string.Empty;
        public string Apellido { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Telefono { get; set; } = string.Empty;  
        public string Password { get; set; } = string.Empty;
        public string DeviceId { get; set; } = string.Empty;
    }
}