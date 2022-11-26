using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Polly;
using System.IdentityModel.Tokens.Jwt;
using Duende.AccessTokenManagement;
using Samples.WeatherApi.MvcClient;

var builder = WebApplication.CreateBuilder(args);

JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

builder.Services.AddDistributedMemoryCache();

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = builder.Configuration.GetServiceUri("auth")!.ToString().TrimEnd('/');

        options.ClientId = "weather-api-mvc-client";
        options.ClientSecret = "secret";
        options.ResponseType = "code";

        options.BackchannelHttpHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };

        options.SaveTokens = true;

        options.Scope.Add("weather-api");
        options.Scope.Add("weather-summary-api");
        options.Scope.Add("offline_access");
        options.Scope.Add("profile");

        options.GetClaimsFromUserInfoEndpoint = true;
    });

// Register and configure Token Management and Weather API HTTP clients for DI
// This is using a separate Client to access API using Client Credentials
builder.Services
    .AddClientCredentialsTokenManagement()
    .AddClient("auth", options =>
    {
        options.TokenEndpoint = $"{builder.Configuration.GetServiceUri("auth")}connect/token";
        options.ClientId = "weather-apis-client";
        options.ClientSecret = "secret";
        options.Scope = "weather-api";
    });
builder.Services
    .AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
    .AcceptAnyServerCertificate()
    .AddTransientHttpErrorPolicy(
        policy => policy.WaitAndRetryAsync(
            new[]
            {
                TimeSpan.FromSeconds(1),
                TimeSpan.FromSeconds(2),
                TimeSpan.FromSeconds(3)
            }));

builder.Services.AddOpenIdConnectAccessTokenManagement();

builder.Services
    .AddClientCredentialsHttpClient("weather-api-client", "auth", configureClient:
        client => client.BaseAddress = new Uri(builder.Configuration.GetServiceUri("weather-api")!.ToString()))
    .AcceptAnyServerCertificate();

builder.Services
    .AddClientCredentialsHttpClient("weather-summary-api-client", "auth",
        client => client.BaseAddress = new Uri(builder.Configuration.GetServiceUri("weather-summary-api")!.ToString()))
    .AcceptAnyServerCertificate();

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapDefaultControllerRoute()
    .RequireAuthorization();

app.Run();
