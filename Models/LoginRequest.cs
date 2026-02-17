namespace GoogleAuth_Backend.Models
{
    public class LoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
    public class LogoutRequest
    {
        public string Token { get; set; }
    }
}
