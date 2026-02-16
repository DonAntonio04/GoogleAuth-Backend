using GoogleAuth_Backend.Services; // Asegúrate de que este namespace coincida con donde creaste el servicio
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 1. Configurar CORS
var misOrigenesPermitidos = "PermitirColaborador";
builder.Services.AddCors(options => {
    options.AddPolicy(name: misOrigenesPermitidos, policy => {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .WithMethods("GET", "POST", "PUT", "DELETE");
    });
});

// 2. Configurar JWT
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

// 3. REGISTRAR EL SERVICIO DE GOOGLE (¡Nuevo!)
builder.Services.AddScoped<IGoogleAuthService, GoogleAuthService>();

var app = builder.Build();

// Middleware para habilitar popups de Google en frontend
app.Use((context, next) =>
{
    context.Response.Headers.Append("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    return next();
});

app.UseCors(misOrigenesPermitidos);
// app.UseHttpsRedirection(); // Mantenlo comentado mientras uses Tailscale/LAN sin SSL
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();