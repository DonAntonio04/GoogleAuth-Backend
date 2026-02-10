using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System;
using RegisterRequest = GoogleAuth_Backend.Models.RegisterRequest;
using GoogleRequest = GoogleAuth_Backend.Models.GoogleRequest;
using ReciboSeguro = GoogleAuth_Backend.Models.ReciboSeguro;
using Google.Apis.Auth; 

using GoogleAuth.Models;
using GoogleAuth_Backend.Models;


using UsuarioSimulado = GoogleAuth.Models.UsuarioSimulado;

namespace GoogleAuth_Backend.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private const string RUTA_ARCHIVO = "usuarios.json";

        private const string SecretKeyDecrypt = "k3P9zR7mW2vL5xN8";

        public AuthController(IConfiguration config)
        {
            _config = config;
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

     
        [HttpPost("google-login")]
        [HttpPost("google-register")]
        public async Task<IActionResult> GoogleAuth([FromBody] GoogleRequest request)
        {
            try
            {
                var settings = new GoogleJsonWebSignature.ValidationSettings()
                {
                    Audience = new List<string> { _config["Authentication:Google:ClientId"] }
                };

                var payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken, settings);
                var json = System.IO.File.Exists(RUTA_ARCHIVO) ? await System.IO.File.ReadAllTextAsync(RUTA_ARCHIVO) : "[]";
                var usuarios = JsonSerializer.Deserialize<List<UsuarioSimulado>>(json) ?? new();

                var usuarioExistente = usuarios.FirstOrDefault(u => u.Email == payload.Email);

                if (usuarioExistente == null)
                {
                    usuarioExistente = new UsuarioSimulado
                    {
                        Nombre = payload.GivenName,
                        Apellido = payload.FamilyName,
                        Email = payload.Email,
                        Telefono = "",
                        Password = "GOOGLE_USER"
                    };
                    usuarios.Add(usuarioExistente);
                    await System.IO.File.WriteAllTextAsync(RUTA_ARCHIVO, JsonSerializer.Serialize(usuarios, new JsonSerializerOptions { WriteIndented = true }));
                }

                var token = GenerarJwtToken(payload.Name, payload.Email);

                return Ok(new
                {
                    Token = token,
                    UserName = payload.Name,
                    Email = payload.Email
                });
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