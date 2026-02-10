using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Configurar CORS
var misOrigenesPermitidos = "PermitirColaborador";
builder.Services.AddCors(options => {
    options.AddPolicy(name: misOrigenesPermitidos, policy => {
        policy.AllowAnyOrigin().AllowAnyHeader().WithMethods("GET", "POST", "PUT", "DELETE");
    });
});

// Configurar JWT
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

app.Use((context, next) =>
{
    context.Response.Headers.Append("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    return next();
});

app.UseCors(misOrigenesPermitidos);
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();