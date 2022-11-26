using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Logging;
using System.IdentityModel.Tokens.Jwt;
using Auth.Data;
using Microsoft.EntityFrameworkCore;

JwtSecurityTokenHandler.DefaultMapInboundClaims = false;
IdentityModelEventSource.ShowPII = true;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("auth-db");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(connectionString);
    options.UseOpenIddict();
});

// builder.Services.AddOpenIddict()
//     // Register the OpenIddict core components.
//     .AddCore(options =>
//     {
//         // Configure OpenIddict to use the Entity Framework Core stores and models.
//         // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
//         options.UseEntityFrameworkCore()
//             .UseDbContext<ApplicationDbContext>();
//     });

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = builder.Configuration.GetServiceUri("auth")!.ToString().TrimEnd('/');

        options.ClientId = "auth-admin-client";
        options.ClientSecret = "secret";
        options.ResponseType = "code";
        options.DisableTelemetry = true;

        options.BackchannelHttpHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };

        options.SaveTokens = true;

        options.Scope.Add("offline_access");
    });

builder.Services.AddRazorPages()
    .AddRazorRuntimeCompilation();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages()
    .RequireAuthorization();

app.Run();
