using GoogleAuth.Models;
using GoogleAuth_Backend.Models;
using GoogleAuth_Backend.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
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
        private readonly AppDbContext _db;
        private readonly IHttpClientFactory _httpClientFactory;
        private const string RUTA_TOKENS_REVOCADOS = "tokens_revocados.json";
        private const string SecretKeyDecrypt = "k3P9zR7mW2vL5xN8";

        public AuthController(IConfiguration config, AppDbContext db, IHttpClientFactory httpClientFactory)
        {
            _config = config;
            _db = db;
            _httpClientFactory = httpClientFactory;
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

                if (request == null || string.IsNullOrEmpty(request.Email))
                    return BadRequest(new { Error = "Datos inválidos." });

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
                if (string.IsNullOrEmpty(request.AccessToken))
                    return BadRequest(new { Error = "Se requiere el access_token de Google." });

                var httpClient = _httpClientFactory.CreateClient();
                httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", request.AccessToken);

                var userInfoResponse = await httpClient.GetStringAsync(
                    "https://www.googleapis.com/oauth2/v3/userinfo"
                );
                var userInfo = JsonDocument.Parse(userInfoResponse);

                string email = userInfo.RootElement.TryGetProperty("email", out var em) ? em.GetString() ?? "" : "";
                string nombre = userInfo.RootElement.TryGetProperty("given_name", out var gn) ? gn.GetString() ?? "" : "";
                string apellido = userInfo.RootElement.TryGetProperty("family_name", out var fn) ? fn.GetString() ?? "" : "";

                if (string.IsNullOrEmpty(email))
                    return BadRequest(new { Error = "No se pudo obtener el email de Google." });

                // Teléfono y fecha de nacimiento (People API) ──
                string telefono = "";
                string fechaNacimiento = "";
                string peopleDebug = "";

                try
                {
                    var peopleClient = _httpClientFactory.CreateClient();
                    peopleClient.DefaultRequestHeaders.Authorization =
                        new AuthenticationHeaderValue("Bearer", request.AccessToken);

                    var peopleUrl = "https://people.googleapis.com/v1/people/me" +
                                    "?personFields=phoneNumbers,birthdays" +
                                    "&sources=READ_SOURCE_TYPE_PROFILE" +
                                    "&sources=READ_SOURCE_TYPE_CONTACT";

                    var peopleResponse = await peopleClient.GetStringAsync(peopleUrl);
                    peopleDebug = peopleResponse;

                    var peopleJson = JsonDocument.Parse(peopleResponse);

                    // Teléfono — busca el marcado como primario, si no toma el primero
                    if (peopleJson.RootElement.TryGetProperty("phoneNumbers", out var phones) &&
                        phones.GetArrayLength() > 0)
                    {
                        foreach (var phone in phones.EnumerateArray())
                        {
                            if (phone.TryGetProperty("metadata", out var meta) &&
                                meta.TryGetProperty("primary", out var primary) &&
                                primary.GetBoolean())
                            {
                                telefono = phone.GetProperty("value").GetString() ?? "";
                                break;
                            }
                        }

                        if (string.IsNullOrEmpty(telefono))
                            telefono = phones[0].GetProperty("value").GetString() ?? "";
                    }

                    // Fecha de nacimiento
                    if (peopleJson.RootElement.TryGetProperty("birthdays", out var birthdays) &&
                        birthdays.GetArrayLength() > 0)
                    {
                        foreach (var birthday in birthdays.EnumerateArray())
                        {
                            if (!birthday.TryGetProperty("date", out var date)) continue;

                            int year = date.TryGetProperty("year", out var y) ? y.GetInt32() : 0;
                            int month = date.TryGetProperty("month", out var m) ? m.GetInt32() : 0;
                            int day = date.TryGetProperty("day", out var d) ? d.GetInt32() : 0;

                            if (year > 0 && month > 0 && day > 0)
                            {
                                fechaNacimiento = $"{year}-{month:D2}-{day:D2}";
                                break;
                            }
                        }
                    }
                }
                catch (Exception peopleEx)
                {
                    Console.WriteLine($"[People API Error]: {peopleEx.Message}");
                    peopleDebug = peopleEx.Message;
                }

                var usuario = _db.Usuarios.FirstOrDefault(u => u.Email == email);

                if (usuario == null)
                {
                    usuario = new UsuarioSimulado
                    {
                        Nombre = nombre,
                        Apellido = apellido,
                        Email = email,
                        Telefono = telefono,
                        Password = "GOOGLE_USER_AUTH"
                    };
                    _db.Usuarios.Add(usuario);
                }
                else
                {
                    if (string.IsNullOrEmpty(usuario.Telefono) && !string.IsNullOrEmpty(telefono))
                        usuario.Telefono = telefono;
                }

                await _db.SaveChangesAsync();

                var jwtToken = GenerarJwtToken(usuario.Nombre, usuario.Email);

                return Ok(new
                {
                    Message = "Autenticación exitosa",
                    Token = jwtToken,
                    User = new
                    {
                        usuario.Nombre,
                        usuario.Apellido,
                        usuario.Email,
                        usuario.Telefono,
                        FechaNacimiento = fechaNacimiento,
                        _PeopleDebug = peopleDebug  // ← quitar cuando confirmes que funciona
                    }
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new
                {
                    Error = "Error procesando la autenticación",
                    Details = ex.Message,
                    Inner = ex.InnerException?.Message
                });
            }
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

 
        private string GenerarJwtToken(string nombre, string email)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name,  nombre),
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