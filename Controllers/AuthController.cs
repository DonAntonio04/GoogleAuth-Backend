using Google.Apis.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GoogleAuth_Backend.Models; 

namespace GoogleAuth_Backend.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private const string RUTA_ARCHIVO = "usuarios.json";
        private const string SecretKeyDecrypt = "k3P9zR7mW2vL5xN8\r\n\r\n";

        public AuthController(IConfiguration config)
        {
            _config = config;
        }

        // Endpoint para Registro Local
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var json = System.IO.File.Exists(RUTA_ARCHIVO) ? await System.IO.File.ReadAllTextAsync(RUTA_ARCHIVO) : "[]";
            var usuarios = JsonSerializer.Deserialize<List<UsuarioSimulado>>(json) ?? new();

            if (usuarios.Any(u => u.Email == request.Email))
                return BadRequest(new { Error = "El correo ya existe." });

            string passwordLimpio = DecryptPassword(request.Password);

            usuarios.Add(new UsuarioSimulado
            {
                Nombre = request.Nombre,
                Email = request.Email,
                Apellido = request.Apellido,
                Telefono = request.Telefono,
                Password = passwordLimpio
            });

            await System.IO.File.WriteAllTextAsync(RUTA_ARCHIVO, JsonSerializer.Serialize(usuarios, new JsonSerializerOptions { WriteIndented = true }));
            return Ok(new { Message = "Usuario registrado." });
        }

        // Endpoint para Google
        [HttpPost("google-login")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleRequest request)
        {
            try
            {
                var settings = new GoogleJsonWebSignature.ValidationSettings()
                {
                    Audience = new List<string> { _config["Authentication:Google:ClientId"] }
                };

                var payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken, settings);

                var token = GenerarJwtToken(payload.Name, payload.Email);

                return Ok(new { Token = token, UserName = payload.Name });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Error = "Token de Google inválido", Details = ex.Message });
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

        private string DecryptPassword(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText)) return cipherText;

            try
            {
                byte[] cipherBytes = Convert.FromBase64String(cipherText);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = Encoding.UTF8.GetBytes(SecretKeyDecrypt);
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;

                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (MemoryStream ms = new MemoryStream(cipherBytes))
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
            catch
            {
                return cipherText;
            }
        }
    }
}