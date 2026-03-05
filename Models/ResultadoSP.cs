namespace GoogleAuth_Backend.Models
{
    public class ResultadoSP
    {
        public string? Resultado { get; set; } // Atrapa el 'OK' o 'Error'
        public int? UsuarioID { get; set; }    // Atrapa el ID generado
        public string? Mensaje { get; set; }   // Atrapa el mensaje de error si el SP falla
    }
}
