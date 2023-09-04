using Auth.Data;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Auth;

// Note: in a real world application, this should be part of a setup script.
public class DatabaseSeedWorker : IHostedService
{
    private const string WeatherApiScope = Permissions.Prefixes.Scope + "weather-api";
    private const string WeatherSummaryApiScope = Permissions.Prefixes.Scope + "weather-summary-api";

    private readonly IServiceProvider _serviceProvider;
    private readonly IConfiguration _configuration;

    public DatabaseSeedWorker(IServiceProvider serviceProvider, IConfiguration configuration)
    {
        _serviceProvider = serviceProvider;
        _configuration = configuration;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var authAdminUrl = _configuration.GetServiceUri("auth-admin")!.ToString();
        var bffClientUrl = _configuration.GetServiceUri("javascriptbff-client")!.ToString();
        var mvcClientUrl = _configuration.GetServiceUri("mvc-client")!.ToString();
        var reactClientUrl = _configuration.GetServiceUri("react-client")!.ToString();

        await using var scope = _serviceProvider.CreateAsyncScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync(cancellationToken);

        var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        if (await scopeManager.FindByNameAsync("weather-api", cancellationToken) == null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "weather-api",
                Description = "Weather API resource",
                DisplayName = "Weather API"
            }, cancellationToken);
        }

        if (await scopeManager.FindByNameAsync("weather-summary-api", cancellationToken) == null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "weather-summary-api",
                Description = "Weather Summary API resource",
                DisplayName = "Weather Summary API"
            }, cancellationToken);
        }

        var clientId = "weather-api-console-client";
        if (await applicationManager.FindByClientIdAsync(clientId, cancellationToken) == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = "secret",
                DisplayName = "Console Client for Weather API",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    WeatherApiScope
                }
            }, cancellationToken);
        }

        clientId = "weather-api-worker-client";
        if (await applicationManager.FindByClientIdAsync(clientId, cancellationToken) == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = "secret",
                DisplayName = "Worker Client for Weather API",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    WeatherApiScope
                }
            }, cancellationToken);
        }

        clientId = "weather-summary-api-console-client";
        if (await applicationManager.FindByClientIdAsync(clientId, cancellationToken) == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = "secret",
                DisplayName = "Console Client for Weather Summary API",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    WeatherSummaryApiScope
                }
            }, cancellationToken);
        }

        clientId = "weather-apis-client";
        if (await applicationManager.FindByClientIdAsync(clientId, cancellationToken) == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = "secret",
                DisplayName = "A Client for both Weather and Weather Summary APIs",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    WeatherApiScope,
                    WeatherSummaryApiScope
                }
            }, cancellationToken);
        }

        clientId = "weather-api-mvc-client";
        if (await applicationManager.FindByClientIdAsync(clientId, cancellationToken) == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = "secret",
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "Interactive web client: MVC application",
                RedirectUris =
                {
                    new Uri($"{mvcClientUrl}signin-oidc")
                },
                PostLogoutRedirectUris =
                {
                    new Uri($"{mvcClientUrl}signout-callback-oidc")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Scopes.OpenId,
                    Scopes.OfflineAccess,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    WeatherApiScope,
                    WeatherSummaryApiScope
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            }, cancellationToken);
        }

        clientId = "bff-client";
        if (await applicationManager.FindByClientIdAsync(clientId, cancellationToken) == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = "secret",
                DisplayName = "BFF client",
                RedirectUris =
                {
                    new Uri($"{bffClientUrl}signin-oidc")
                },
                PostLogoutRedirectUris =
                {
                    new Uri($"{bffClientUrl}signout-callback-oidc")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Scopes.OpenId,
                    Scopes.OfflineAccess,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    WeatherApiScope
                }
            }, cancellationToken);
        }

        clientId = "react-client";
        if (await applicationManager.FindByClientIdAsync(clientId, cancellationToken) == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                DisplayName = "React client",
                RedirectUris =
                {
                    new Uri($"{reactClientUrl}signin-oidc")
                },
                PostLogoutRedirectUris =
                {
                    new Uri($"{reactClientUrl}signout-callback-oidc")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Scopes.OpenId,
                    Scopes.OfflineAccess,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    WeatherApiScope
                }
            }, cancellationToken);
        }

        clientId = "wpf-client";
        if (await applicationManager.FindByClientIdAsync(clientId, cancellationToken) == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                //ClientSecret = "secret",
                DisplayName = "WPF device client",
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Device,
                    Permissions.GrantTypes.DeviceCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Scopes.OpenId,
                    Scopes.OfflineAccess,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    WeatherApiScope
                }
            }, cancellationToken);
        }

        clientId = "auth-admin-client";
        if (await applicationManager.FindByClientIdAsync(clientId, cancellationToken) == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = "secret",
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "Auth Admin application",
                RedirectUris =
                {
                    new Uri($"{authAdminUrl}signin-oidc")
                },
                PostLogoutRedirectUris =
                {
                    new Uri($"{authAdminUrl}signout-callback-oidc")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Scopes.OpenId,
                    Scopes.OfflineAccess,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            }, cancellationToken);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
