using System.Security.Claims;
using Auth.Extensions;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Auth.Controllers;

public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager, IOpenIddictScopeManager scopeManager)
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
    }

    [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()!;

        if (request.IsClientCredentialsGrantType())
        {
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId!);
            if (application == null)
            {
                throw new InvalidOperationException("The application details cannot be found in the database.");
            }

            // Create the claims-based identity that will be used by OpenIddict to generate tokens.
            var identity = new ClaimsIdentity(
                TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

            // Add the claims that will be persisted in the tokens (use the client_id as the subject identifier).
            identity.AddClaim(
                Claims.Subject, (await _applicationManager.GetClientIdAsync(application))!,
                Destinations.AccessToken, Destinations.IdentityToken);
            identity.AddClaim(
                Claims.Name, (await _applicationManager.GetDisplayNameAsync(application))!,
                Destinations.AccessToken, Destinations.IdentityToken);

            // Set the list of scopes granted to the client application in access_token.
            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes().ToArray());
            principal.SetResources(await _scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim));
            }

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new NotImplementedException("The specified grant type is not implemented.");
    }

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.
        return claim.Type switch
        {
            Claims.Name or Claims.Subject => new[] { Destinations.AccessToken, Destinations.IdentityToken },
            _ => new[] { Destinations.AccessToken },
        };
    }
}
