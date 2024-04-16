using Exo.WebApi.Contexts;
using Exo.WebApi.Repositories;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<ExoContext, ExoContext>();
builder.Services.AddControllers();


// Forma de autenticacão.
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "JwtBearer";
    options.DefaultChallengeScheme = "JwtBearer";
})
// Parâmetros de validacão do token.
.AddJwtBearer("JwtBearer", options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // Valida solicitador.
        ValidateIssuer = true,
        // Valida o recebendor.
        ValidateAudience = true,
        // Define a validação do tempo de expiração.
        ValidateLifetime = true,
        // Criptografia e validação da chave de autenticacão.
        IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("exoapi-chaveautenticacao")),
        // Validação do tempo de expiração do token.
        ClockSkew = TimeSpan.FromMinutes(30),
        // Nome da origem.
        ValidIssuer = "exoapi.webapi",
        // Nome para o destino.
        ValidAudience = "exoapi.webapi"
    };
});


builder.Services.AddTransient<ProjetoRepository, ProjetoRepository>();
builder.Services.AddTransient<UsuarioRepository, UsuarioRepository>();


var app = builder.Build();

app.UseRouting();

// Habilitação da autenticação.
app.UseAuthentication();
// Habilitação da autorização.
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});

app.Run();
