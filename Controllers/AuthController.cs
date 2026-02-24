using GoogleAuth.Models;
using GoogleAuth_Backend.Models;
using GoogleAuth_Backend.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Numerics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GoogleRequest = GoogleAuth_Backend.Models.GoogleRequest;
using LoginRequest = GoogleAuth_Backend.Models.LoginRequest;
using RegisterRequest = GoogleAuth_Backend.Models.RegisterRequest;
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

        private const string SecretKey = "k3P9zR7mW2vL5xN8";

        public AuthController(IConfiguration config, AppDbContext db, IHttpClientFactory httpClientFactory)
        {
            _config = config;
            _db = db;
            _httpClientFactory = httpClientFactory;
        }

  
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] EncryptedPayload payload)
        {
            try
            {
                if (payload == null || string.IsNullOrEmpty(payload.Data))
                    return BadRequest(new { Error = "No se recibieron datos cifrados." });

                string jsonDescifrado = Decrypt(payload.Data); //punto de interrupcion

                if (string.IsNullOrEmpty(jsonDescifrado))
                    return BadRequest(new { Error = "La llave de encriptación no coincide o los datos están corruptos." });

                var request = JsonSerializer.Deserialize<RegisterRequest>(
                    jsonDescifrado,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );

                if (request == null || string.IsNullOrEmpty(request.Email))
                    return BadRequest(new { Error = "Datos inválidos o el correo está vacío." });

                if (_db.Usuarios.Any(u => u.Email == request.Email))
                    return BadRequest(new { Error = "El correo ya existe." });

                string passwordHash = HashPassword(request.Password);

                _db.Usuarios.Add(new UsuarioSimulado
                {
                    Nombre = request.Nombre,
                    Apellido = request.Apellido,
                    Email = request.Email,
                    Telefono = request.Telefono,
                    Password = passwordHash
                });

                await _db.SaveChangesAsync();

                var respuestaObj = new
                {
                    Message = "Usuario registrado exitosamente.",
                    Email = request.Email,
                    Nombre = request.Nombre
                };

                string respuestaCifrada = Encrypt(JsonSerializer.Serialize(respuestaObj));

                return Ok(new { Data = respuestaCifrada });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Error = "Error de seguridad o datos inválidos", Detalle = ex.Message });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] EncryptedPayload payload)
        {
            try
            {
                if (payload == null || string.IsNullOrEmpty(payload.                                                                                                         Data))
                    return BadRequest(new { Error = "No se recibieron credenciales cifradas." });

                string jsonDescifrado = Decrypt(payload.Data);

                if (string.IsNullOrEmpty(jsonDescifrado))
                    return BadRequest(new { Error = "Error al descifrar las credenciales." });

                var request = JsonSerializer.Deserialize<LoginRequest>(
                    jsonDescifrado,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );

                if (request == null || string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
                    return BadRequest(new { Error = "Datos incompletos." });

                var usuario = _db.Usuarios.FirstOrDefault(u => u.Email == request.Email);

                if (usuario == null)
                    return Unauthorized(new { Error = "Correo o contraseña incorrectos." });

                string passwordHashIntento = HashPassword(request.Password);

                if (usuario.Password != passwordHashIntento)
                    return Unauthorized(new { Error = "Correo o contraseña incorrectos." });

                var jwtToken = GenerarJwtToken(usuario.Nombre, usuario.Email);

                var respuestaObj = new
                {
                    Token = jwtToken,
                    Nombre = usuario.Nombre,
                    Apellido = usuario.Apellido,
                    Email = usuario.Email,
                    Telefono = usuario.Telefono,

                };

                string respuestaCifrada = Encrypt(JsonSerializer.Serialize(respuestaObj));

                return Ok(new { Data = respuestaCifrada });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Error = "Error procesando el login", Detalle = ex.Message });
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

                string telefono = "";
                string fechaNacimiento = "";

                try
                {
                    var peopleClient = _httpClientFactory.CreateClient();
                    peopleClient.DefaultRequestHeaders.Authorization =
                        new AuthenticationHeaderValue("Bearer", request.AccessToken);

                    var peopleUrl = "https://people.googleapis.com/v1/people/me?personFields=phoneNumbers,birthdays";
                    var peopleResponse = await peopleClient.GetStringAsync(peopleUrl);
                    var peopleJson = JsonDocument.Parse(peopleResponse);

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
                        Password = HashPassword(Guid.NewGuid().ToString())
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

                var respuestaObj = new
                {
                    Message = "Autenticación exitosa",
                    Token = jwtToken,
                    Nombre = usuario.Nombre,
                    Apellido = usuario.Apellido,
                    Email = usuario.Email,
                    Telefono = usuario.Telefono,
                    FechaNacimiento = fechaNacimiento
                };

                string respuestaCifrada = Encrypt(JsonSerializer.Serialize(respuestaObj));

                return Ok(new { Data = respuestaCifrada });
            }
            catch (Exception ex)
            {
                return BadRequest(new
                {
                    Error = "Error procesando la autenticación",
                    Detail = ex.Message,
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

        //Preparar la llave para encriptar y desencriptar
        private byte[] DerivarLlaveAes()
        {
            byte[] llave16Bytes = Encoding.UTF8.GetBytes(SecretKey);
            return llave16Bytes;
        }

        //Encriptamos 
        private string Encrypt(string plainText)
        {
            using var aes = Aes.Create();
            aes.Key = DerivarLlaveAes();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;

            byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
            using var encryptor = aes.CreateEncryptor();
            byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);

            string base64Result = Convert.ToBase64String(encryptedBytes);
            return base64Result;
        }

        private string? Decrypt(string cipherTextBase64)
        {
            try
            {
          
                byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);

                using var aes = Aes.Create();
                aes.Key = DerivarLlaveAes();
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.PKCS7;

                using var decryptor = aes.CreateDecryptor();
                byte[] result = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

          
                string json = Encoding.UTF8.GetString(result); //punto de interrupcion

                JsonDocument.Parse(json); // Valida que sea JSON bien formado
                return json;
            }
            catch (Exception ex)
            {
             
                Console.WriteLine($"[Decrypt Error]: {ex.Message}"); //punto de interupcion
                return null;
            }
        }

        private string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();

            byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
             string hashResult = Convert.ToBase64String(hashBytes); //punto de interupcion
            return hashResult;
        }

        private string GenerarJwtToken(string nombre, string email)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name,             nombre),
                new Claim(ClaimTypes.Email,            email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );

            string tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            return tokenString;
        }
    }
}