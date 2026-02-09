using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Google.Apis.Auth;
using GoogleAuth.Models;

var builder = WebApplication.CreateBuilder(args);

// 1. Configurar CORS para Angular
var misOrigenesPermitidos = "PermitirAngular";
builder.Services.AddCors(options => {
    options.AddPolicy(name: misOrigenesPermitidos, policy => {
        policy.WithOrigins("http://localhost:4200")
              .AllowAnyHeader()
              .WithMethods("GET", "POST", "PUT", "DELETE");
    });
});

// 2. AGREGAR ESTO: Configuración de servicios de Autenticación
// Sin esto, app.UseAuthentication() no sabe qué hacer.
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

// 3. AGREGAR ESTO: Middleware de COOP (Debe ir antes de otros)
app.Use((context, next) =>
{
    context.Response.Headers.Append("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    return next();
});

app.UseHttpsRedirection(); // Asegura el uso de HTTPS (Puerto 7159)
app.UseCors(misOrigenesPermitidos);
app.UseAuthentication();
app.UseAuthorization();

const string RUTA_ARCHIVO = "usuarios.json";

// --- ENDPOINTS ---

app.MapPost("/api/auth/register", async (RegisterRequest request) => {
    var json = File.Exists(RUTA_ARCHIVO) ? await File.ReadAllTextAsync(RUTA_ARCHIVO) : "[]";
    var usuarios = JsonSerializer.Deserialize<List<UsuarioSimulado>>(json) ?? new();

    if (usuarios.Any(u => u.Email == request.Email))
        return Results.BadRequest(new { Error = "El correo ya existe." });

    usuarios.Add(new UsuarioSimulado
    {
        Nombre = request.Nombre,
        Email = request.Email,
        Password = request.Password
    });

    await File.WriteAllTextAsync(RUTA_ARCHIVO, JsonSerializer.Serialize(usuarios, new JsonSerializerOptions { WriteIndented = true }));
    return Results.Ok(new { Message = "Usuario registrado." });
});

app.MapPost("/api/auth/google-login", async (GoogleRequest request, IConfiguration config) => {
    try
    {
        var settings = new GoogleJsonWebSignature.ValidationSettings()
        {
            Audience = new List<string> { config["Authentication:Google:ClientId"] }
        };
        var payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken, settings);
        var token = GenerarJwt(payload.Name, payload.Email, config);
        return Results.Ok(new { Token = token, UserName = payload.Name });
    }
    catch (Exception ex)
    {
        // Cambiado para que puedas ver el error real en la consola de depuración
        return Results.BadRequest(new { Error = "Token de Google inválido", Details = ex.Message });
    }
});

app.Run();

string GenerarJwt(string nombre, string email, IConfiguration config)
{
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: config["Jwt:Issuer"],
        audience: config["Jwt:Audience"],
        claims: new[] { new Claim(ClaimTypes.Name, nombre), new Claim(ClaimTypes.Email, email) },
        expires: DateTime.Now.AddDays(1),
        signingCredentials: creds
    );
    return new JwtSecurityTokenHandler().WriteToken(token);
}

public record RegisterRequest(string Nombre, string Email, string Password);
public record GoogleRequest(string IdToken);