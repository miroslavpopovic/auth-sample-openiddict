using Duende.Bff;
using Duende.Bff.Yarp;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Samples.WeatherApi.JavaScriptBffClient;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddControllers();
builder.Services.AddAuthorization();

builder.Services.AddBff()
    .AddRemoteApis();
// HACK: Allow self-signed certificates for the remote API server
builder.Services.Replace(ServiceDescriptor.Transient<IHttpMessageInvokerFactory, DangerousHttpMessageInvokerFactory>());

JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.Authority = builder.Configuration.GetServiceUri("auth")!.ToString().TrimEnd('/');

    options.ClientId = "bff-client";
    options.ClientSecret = "secret";
    options.ResponseType = "code";

    options.BackchannelHttpHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    };

    options.SaveTokens = true;

    options.Scope.Add("weather-api");

    options.GetClaimsFromUserInfoEndpoint = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseBff();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.MapBffManagementEndpoints();

app.MapRemoteBffApiEndpoint(
        "/remote", builder.Configuration.GetServiceUri("weather-api")!.ToString().TrimEnd('/'))
    .RequireAccessToken();

app.Run();
