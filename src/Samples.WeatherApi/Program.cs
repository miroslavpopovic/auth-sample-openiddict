using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Samples.WeatherApi.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSwagger(builder.Configuration);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.Authority = builder.Configuration.GetServiceUri("auth")!.ToString().TrimEnd('/');
        options.MapInboundClaims = true;

        options.BackchannelHttpHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };

        // To debug various token validation issues, use events
        options.Events = new JwtBearerEvents
        {
            // OnAuthenticationFailed = context =>
            // {
            //     var error = context.Exception;
            //     return Task.CompletedTask;
            // },
            // OnForbidden = context =>
            // {
            //     var request = context.Request;
            //     return Task.CompletedTask;
            // },
            OnTokenValidated = async (context) =>
            {
                // OpenIddict sends scope as one claim with space separated values
                // ASP.NET Core validation expects scope claim to be an array of values
                // Split the scope claim to an array to make it pass validation
                // This is only an issue when multiple scopes are used
                // https://stackoverflow.com/questions/54852094/asp-net-core-requireclaim-scope-with-multiple-scopes
                if (context.Principal?.Identity is ClaimsIdentity claimsIdentity)
                {
                    var scopeClaims = claimsIdentity.FindFirst("scope");
                    if (scopeClaims is not null)
                    {
                        claimsIdentity.RemoveClaim(scopeClaims);
                        claimsIdentity.AddClaims(scopeClaims.Value.Split(' ').Select(scope => new Claim("scope", scope)));
                    }
                }
                await Task.CompletedTask;
            }
        };

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ApiScope", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("scope", "weather-api");
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwaggerWithOAuth(app.Configuration);
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers()
    .RequireAuthorization("ApiScope");

app.Run();
