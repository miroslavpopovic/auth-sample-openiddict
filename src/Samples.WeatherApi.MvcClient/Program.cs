using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Polly;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

builder.Services.AddAuthentication(options =>
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
// TODO: Replace this with Duende.AccessTokenManagement once it's out of the preview phase
// https://blog.duendesoftware.com/posts/20220804_datm/
builder.Services
    .AddAccessTokenManagement(
        options =>
        {
            options.Client.Clients.Add(
                "auth", new ClientCredentialsTokenRequest
                {
                    Address = $"{builder.Configuration.GetServiceUri("auth")}connect/token",
                    ClientId = "weather-apis-client",
                    ClientSecret = "secret",
                    Scope = "weather-api"
                });
        })
    .ConfigureBackchannelHttpClient()
    .ConfigurePrimaryHttpMessageHandler(
        () => new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        })
    .AddTransientHttpErrorPolicy(
        policy =>
            policy.WaitAndRetryAsync(
                new[]
                {
                    TimeSpan.FromSeconds(1),
                    TimeSpan.FromSeconds(2),
                    TimeSpan.FromSeconds(3)
                }));

builder.Services
    .AddClientAccessTokenHttpClient(
        "weather-api-client",
        configureClient: client =>
        {
            client.BaseAddress = new Uri(builder.Configuration.GetServiceUri("weather-api")!.ToString());
        })
    .ConfigurePrimaryHttpMessageHandler(
        () => new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        });

builder.Services
    .AddClientAccessTokenHttpClient(
        "weather-summary-api-client",
        configureClient: client =>
        {
            client.BaseAddress = new Uri(builder.Configuration.GetServiceUri("weather-summary-api")!.ToString());
        })
    .ConfigurePrimaryHttpMessageHandler(
        () => new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        });

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

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute()
        .RequireAuthorization();
});

app.Run();
