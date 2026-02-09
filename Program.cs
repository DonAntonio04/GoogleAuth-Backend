using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Google.Apis.Auth;
using GoogleAuth.Models;

var builder = WebApplication.CreateBuilder(args);

// 1. Configurar política de CORS
var misOrigenesPermitidos = "PermitirColaborador";
builder.Services.AddCors(options => {
    options.AddPolicy(name: misOrigenesPermitidos, policy => {
        // Permitimos cualquier origen, encabezado y método para facilitar las pruebas locales
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .WithMethods("GET", "POST", "PUT", "DELETE");
    });
});

// 2. Configuración de servicios de Autenticación (JWT)
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddControllers();

var app = builder.Build();

// --- MIDDLEWARES (El orden es vital aquí) ---

// A. Middleware de COOP para autenticación de Google
app.Use((context, next) =>
{
    context.Response.Headers.Append("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    return next();
});

// B. CORS debe ir ANTES de la autenticación y redirección
app.UseCors(misOrigenesPermitidos);

// C. Otros Middlewares del sistema
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

const string RUTA_ARCHIVO = "usuarios.json";

// --- ENDPOINTS ---

// Registro de usuario local
app.MapPost("/api/auth/register", async (RegisterRequest request) => {
    var json = File.Exists(RUTA_ARCHIVO) ? await File.ReadAllTextAsync(RUTA_ARCHIVO) : "[]";
    var usuarios = JsonSerializer.Deserialize<List<UsuarioSimulado>>(json) ?? new();

    if (usuarios.Any(u => u.Email == request.Email))
        return Results.BadRequest(new { Error = "El correo ya existe." });

    usuarios.Add(new UsuarioSimulado
    {
        Nombre = request.Nombre,
        Email = request.Email,
        Apellido = request.Apellido,
        Telefono = request.Telefono,
        Password = request.Password
    });

    await File.WriteAllTextAsync(RUTA_ARCHIVO, JsonSerializer.Serialize(usuarios, new JsonSerializerOptions { WriteIndented = true }));
    return Results.Ok(new { Message = "Usuario registrado." });
});

// Login con Google
app.MapPost("/api/auth/google-login", async (GoogleRequest request, IConfiguration config) => {
    try
    {
        var settings = new GoogleJsonWebSignature.ValidationSettings()
        {
            Audience = new List<string> { config["Authentication:Google:ClientId"] }
        };
        var payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken, settings); //aqui av el punto de interrupcion

        var token = GenerarJwt(payload.Name, payload.Email, config);
        return Results.Ok(new { Token = token, UserName = payload.Name });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { Error = "Token de Google inválido", Details = ex.Message });
    }
});

app.Run();

// --- FUNCIONES AUXILIARES ---

string GenerarJwt(string nombre, string email, IConfiguration config)
{
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: config["Jwt:Issuer"],
        audience: config["Jwt:Audience"],
        claims: new[] {
            new Claim(ClaimTypes.Name, nombre),
            new Claim(ClaimTypes.Email, email)
        },
        expires: DateTime.Now.AddDays(1),
        signingCredentials: creds
    );
    return new JwtSecurityTokenHandler().WriteToken(token);
}

// DTOs necesarios para los endpoints
public record RegisterRequest(string Nombre, string Apellido, string Email, string Telefono, string Password); 
public record GoogleRequest(string IdToken);