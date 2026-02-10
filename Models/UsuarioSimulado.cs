    namespace GoogleAuth.Models
    {
        public class UsuarioSimulado
        {
            public string Nombre { get; set; } = string.Empty;
            public string Apellido { get; set; } = string.Empty;
            public string Email { get; set; } = string.Empty;
            public string Telefono { get; set; } = string.Empty;
            public string Password { get; set; } = string.Empty;

      
        }

        public class ReciboSeguro
        {
            public string Data { get; set; }
        }

    // Este modelo sirve para recibir los datos DESPUÉS de descifrar
    public class RegisterRequest
    {
        public string Nombre { get; set; }
        public string Apellido { get; set; }
        public string Email { get; set; }
        public string Telefono { get; set; }
        public string Password { get; set; }
    }

    public class GoogleRequest
    {
        public string IdToken { get; set; }
    }
}