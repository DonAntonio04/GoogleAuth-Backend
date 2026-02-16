using Google.Apis.Auth;

namespace GoogleAuth_Backend.Services
{
    public interface IGoogleAuthService
    {
        Task<GoogleJsonWebSignature.Payload> ValidarTokenGoogle(string idToken);
    }

    public class GoogleAuthService : IGoogleAuthService
    {
        private readonly IConfiguration _config;

        public GoogleAuthService(IConfiguration config)
        {
            _config = config;
        }

        public async Task<GoogleJsonWebSignature.Payload> ValidarTokenGoogle(string idToken)
        {
            var clientIdAngular = _config["Authentication:Google:ClientId"];
            var clientIdReact = _config["Authentication:Google:ClientIdReact"];

            var settings = new GoogleJsonWebSignature.ValidationSettings()
            {
                Audience = new List<string>
                {
                    clientIdAngular, 
                    clientIdReact    
                }
            };

            var payload = await GoogleJsonWebSignature.ValidateAsync(idToken, settings);

            return payload;
        }
    }
}