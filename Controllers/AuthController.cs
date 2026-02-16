using Google.Apis.Auth;
using GoogleAuth.Models;
using GoogleAuth_Backend.Models;
using GoogleAuth_Backend.Services; // <--- Importamos el servicio
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
        private readonly IGoogleAuthService _googleService; // <--- Inyección del servicio
        private const string RUTA_ARCHIVO = "usuarios.json";
        private const string SecretKeyDecrypt = "k3P9zR7mW2vL5xN8";

        // Constructor actualizado
        public AuthController(IConfiguration config, IGoogleAuthService googleService)
        {
            _config = config;
            _googleService = googleService;
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

                var json = System.IO.File.Exists(RUTA_ARCHIVO) ? await System.IO.File.ReadAllTextAsync(RUTA_ARCHIVO) : "[]";
                var usuarios = JsonSerializer.Deserialize<List<UsuarioSimulado>>(json) ?? new();

                if (usuarios.Any(u => u.Email == request.Email))
                    return BadRequest(new { Error = "El correo ya existe." });

                usuarios.Add(new UsuarioSimulado
                {
                    Nombre = request.Nombre,
                    Email = request.Email,
                    Apellido = request.Apellido,
                    Telefono = request.Telefono,
                    Password = request.Password
                });

                await System.IO.File.WriteAllTextAsync(RUTA_ARCHIVO, JsonSerializer.Serialize(usuarios, new JsonSerializerOptions { WriteIndented = true }));
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
                var json = System.IO.File.Exists(RUTA_ARCHIVO) ? await System.IO.File.ReadAllTextAsync(RUTA_ARCHIVO) : "[]";
                var usuarios = JsonSerializer.Deserialize<List<UsuarioSimulado>>(json) ?? new();

                var usuario = usuarios.FirstOrDefault(u => u.Email == request.Email && u.Password == request.Password);

                if (usuario == null)
                {
                    return Unauthorized(new { Error = "Credenciales incorrectas", Message = "Correo o contraseña no válidos." });
                }

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

        // --- LOGIN CON GOOGLE ---
        [HttpPost("google-login")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleRequest request)
        {
            try
            {
                // Usamos el servicio inyectado
                var payload = await _googleService.ValidarTokenGoogle(request.IdToken);

                var json = System.IO.File.Exists(RUTA_ARCHIVO) ? await System.IO.File.ReadAllTextAsync(RUTA_ARCHIVO) : "[]";
                var usuarios = JsonSerializer.Deserialize<List<UsuarioSimulado>>(json) ?? new();

                var usuarioExistente = usuarios.FirstOrDefault(u => u.Email == payload.Email);

                if (usuarioExistente == null)
                {
                    return Unauthorized(new
                    {
                        Error = "Usuario no registrado",
                        Message = "Debes registrarte con Google antes de iniciar sesión."
                    });
                }

                var token = GenerarJwtToken(payload.Name, payload.Email);

                return Ok(new
                {
                    Token = token,
                    UserName = usuarioExistente.Nombre,
                    Email = usuarioExistente.Email
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Error = "Token inválido", Details = ex.Message });
            }
        }

        // --- REGISTRO CON GOOGLE ---
        [HttpPost("google-register")]
        public async Task<IActionResult> GoogleRegister([FromBody] GoogleRequest request)
        {
            try
            {
                // Usamos el servicio inyectado
                var payload = await _googleService.ValidarTokenGoogle(request.IdToken);

                var json = System.IO.File.Exists(RUTA_ARCHIVO) ? await System.IO.File.ReadAllTextAsync(RUTA_ARCHIVO) : "[]";
                var usuarios = JsonSerializer.Deserialize<List<UsuarioSimulado>>(json) ?? new();

                if (usuarios.Any(u => u.Email == payload.Email))
                {
                    return BadRequest(new { Error = "El usuario ya está registrado. Por favor, inicia sesión." });
                }

                // Creamos el usuario (con manejo de nulos por seguridad)
                var nuevoUsuario = new UsuarioSimulado
                {
                    Nombre = payload.GivenName ?? "Usuario Google",
                    Apellido = payload.FamilyName ?? "",
                    Email = payload.Email,
                    Telefono = "",
                    Password = "GOOGLE_USER"
                };

                usuarios.Add(nuevoUsuario);
                await System.IO.File.WriteAllTextAsync(RUTA_ARCHIVO, JsonSerializer.Serialize(usuarios, new JsonSerializerOptions { WriteIndented = true }));

                var token = GenerarJwtToken(payload.Name, payload.Email);
                return Ok(new { Message = "Usuario registrado correctamente", Token = token });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Error = "Error en el registro con Google", Details = ex.Message });
            }
        }

        private string GenerarJwtToken(string nombre, string email)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: new[] {
                    new Claim(ClaimTypes.Name, nombre),
                    new Claim(ClaimTypes.Email, email)
                },
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
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