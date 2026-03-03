using GoogleAuth_Backend.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

var misOrigenesPermitidos = "PermitirColaborador";
builder.Services.AddCors(options => {
    options.AddPolicy(name: misOrigenesPermitidos, policy => {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .WithMethods("GET", "POST", "PUT", "DELETE");
    });
});

builder.Configuration["Jwt:Key"] = "X7k#mP2$nQ9wL4vR8tY3uA6jF1eD5hB0";
builder.Configuration["Jwt:Issuer"] = "https://localhost:7159";
builder.Configuration["Jwt:Audience"] = "MiAppAngular";

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
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
        };
    });

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
    });

builder.Services.AddScoped<IGoogleAuthService, GoogleAuthService>();
builder.Services.AddHttpClient();

var app = builder.Build();

app.Use((context, next) =>
{
    // Registramos un callback que se ejecuta justo antes de enviar los headers al cliente
    context.Response.OnStarting(() =>
    {
        // Usamos el indexador [] en lugar de .Append() para evitar errores de llaves duplicadas
        context.Response.Headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups";
        return Task.CompletedTask;
    });

    return next();
});

app.UseCors(misOrigenesPermitidos);
// app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();