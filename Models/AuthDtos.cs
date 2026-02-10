namespace GoogleAuth_Backend.Models
{
    
    public record RegisterRequest(string Nombre, string Apellido, string Email, string Telefono, string Password);
    public record GoogleRequest(string IdToken);

    public class UsuarioSimulado
    {
        public string Nombre { get; set; }
        public string Apellido { get; set; }
        public string Email { get; set; }
        public string Telefono { get; set; }
        public string Password { get; set; }
    }
}