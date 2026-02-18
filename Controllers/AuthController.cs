using Google.Apis.Auth;
using GoogleAuth.Models;
using GoogleAuth_Backend.Models;
using GoogleAuth_Backend.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GoogleRequest = GoogleAuth_Backend.Models.GoogleRequest;
using ReciboSeguro = GoogleAuth_Backend.Models.ReciboSeguro;
using RegisterRequest = GoogleAuth_Backend.Models.RegisterRequest;
using LoginRequest = GoogleAuth_Backend.Models.LoginRequest;
using UsuarioSimulado = GoogleAuth.Models.UsuarioSimulado;

namespace GoogleAuth_Backend.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly IGoogleAuthService _googleService;
        private readonly AppDbContext _db;
        private const string RUTA_TOKENS_REVOCADOS = "tokens_revocados.json";
        private const string SecretKeyDecrypt = "k3P9zR7mW2vL5xN8";

        public AuthController(IConfiguration config, IGoogleAuthService googleService, AppDbContext db)
        {
            _config = config;
            _googleService = googleService;
            _db = db;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] ReciboSeguro inputCifrado)
        {
            try
            {
                string jsonDecifrado = DecryptGeneral(inputCifrado.Data);

                var request = JsonSerializer.Deserialize<RegisterRequest>(jsonDecifrado, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (_db.Usuarios.Any(u => u.Email == request.Email))
                    return BadRequest(new { Error = "El correo ya existe." });

                _db.Usuarios.Add(new UsuarioSimulado
                {
                    Nombre = request.Nombre,
                    Email = request.Email,
                    Apellido = request.Apellido,
                    Telefono = request.Telefono,
                    Password = request.Password
                });

                await _db.SaveChangesAsync();
                return Ok(new { Message = "Usuario registrado." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Error = "Error de seguridad o datos inválidos", Detalle = ex.Message });
            }
        }

        [HttpPost("local-login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                var usuario = _db.Usuarios.FirstOrDefault(u => u.Email == request.Email && u.Password == request.Password);

                if (usuario == null)
                    return Unauthorized(new { Error = "Credenciales incorrectas", Message = "Correo o contraseña no válidos." });

                var token = GenerarJwtToken(usuario.Nombre, usuario.Email);

                return Ok(new
                {
                    Token = token,
                    UserName = usuario.Nombre,
                    Email = usuario.Email
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Error = "Error al iniciar sesión", Details = ex.Message });
            }
        }

        [HttpPost("google-auth")]
        public async Task<IActionResult> GoogleAuth([FromBody] GoogleRequest request)
        {
            try
            {
                var payload = await _googleService.ValidarTokenGoogle(request.IdToken);

                if (payload == null)
                    return BadRequest(new { Error = "El token de Google no es válido o ha expirado." });

                var usuario = _db.Usuarios.FirstOrDefault(u => u.Email == payload.Email);

                if (usuario == null)
                {
                    usuario = new UsuarioSimulado
                    {
                        Nombre = payload.GivenName ?? payload.Name ?? "Usuario Google",
                        Apellido = payload.FamilyName ?? "",
                        Email = payload.Email,
                        Telefono = "",
                        Password = "GOOGLE_USER_AUTH"
                    };

                    _db.Usuarios.Add(usuario);
                    await _db.SaveChangesAsync();
                }

                var token = GenerarJwtToken(usuario.Nombre, usuario.Email);

                return Ok(new
                {
                    Message = "Autenticación exitosa",
                    Token = token,
                    User = new { usuario.Nombre, usuario.Email }
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Error = "Error procesando la autenticación", Details = ex.Message });
            }
        }

        private string GenerarJwtToken(string nombre, string email)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, nombre),
                new Claim(ClaimTypes.Email, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
        {
            try
            {
                if (string.IsNullOrEmpty(request.Token))
                    return BadRequest(new { Error = "El token es requerido." });

                var json = System.IO.File.Exists(RUTA_TOKENS_REVOCADOS)
                           ? await System.IO.File.ReadAllTextAsync(RUTA_TOKENS_REVOCADOS)
                           : "[]";

                var tokensRevocados = JsonSerializer.Deserialize<List<string>>(json) ?? new();

                if (!tokensRevocados.Contains(request.Token))
                {
                    tokensRevocados.Add(request.Token);
                    await System.IO.File.WriteAllTextAsync(
                        RUTA_TOKENS_REVOCADOS,
                        JsonSerializer.Serialize(tokensRevocados, new JsonSerializerOptions { WriteIndented = true })
                    );
                }

                return Ok(new { Message = "Sesión cerrada correctamente en el servidor." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Error = "Error al procesar logout", Details = ex.Message });
            }
        }

        private string DecryptGeneral(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText)) return "{}";

            try
            {
                byte[] cipherBytes = Convert.FromBase64String(cipherText);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = Encoding.UTF8.GetBytes(SecretKeyDecrypt);
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var descifrador = aes.CreateDecryptor())
                    {
                        byte[] resultado = descifrador.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                        return Encoding.UTF8.GetString(resultado);
                    }
                }
            }
            catch
            {
                return "{}";
            }
        }
    }
}