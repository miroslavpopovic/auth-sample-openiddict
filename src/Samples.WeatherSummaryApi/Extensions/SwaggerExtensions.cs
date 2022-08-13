using Microsoft.OpenApi.Models;
using Samples.WeatherSummaryApi.Filters;

namespace Samples.WeatherSummaryApi.Extensions;

public static class SwaggerExtensions
{
    public static void AddSwagger(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1", new OpenApiInfo { Title = "Samples.WeatherSummaryApi", Version = "v1" });

            var issuer = configuration.GetServiceUri("auth")!.ToString().TrimEnd('/');

            options.AddSecurityDefinition("oauth2",
                new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.OAuth2,
                    Flows = new OpenApiOAuthFlows
                    {
                        ClientCredentials = new OpenApiOAuthFlow
                        {
                            AuthorizationUrl = new Uri($"{issuer}/connect/auth"),
                            TokenUrl = new Uri($"{issuer}/connect/token"),
                            Scopes = new Dictionary<string, string> { { "weather-summary-api", "Weather Summary API" } }
                        }
                    }
                });

            options.OperationFilter<AuthorizeCheckOperationFilter>();
        });
    }

    public static void UseSwaggerWithOAuth(this IApplicationBuilder app, IConfiguration configuration)
    {
        app.UseSwagger();
        app.UseSwaggerUI(options =>
        {
            options.SwaggerEndpoint("/swagger/v1/swagger.json", "Samples.WeatherSummaryApi v1");

            options.OAuthScopes("weather-summary-api");
            options.OAuthClientId(configuration.GetValue<string>("Swagger:ClientId"));
            options.OAuthClientSecret(configuration.GetValue<string>("Swagger:ClientSecret"));
        });
    }
}
