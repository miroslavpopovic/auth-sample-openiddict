using Auth.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Auth.Controllers;

public class UserInfoController : Controller
{
    private readonly UserManager<AuthUser> _userManager;

    public UserInfoController(UserManager<AuthUser> userManager)
        => _userManager = userManager;

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo"), Produces("application/json")]
    public async Task<IActionResult> Userinfo()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The specified access token is bound to an account that no longer exists."
                }));
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
            [OpenIddictConstants.Claims.Subject] = await _userManager.GetUserIdAsync(user)
        };

        if (User.HasScope(OpenIddictConstants.Permissions.Scopes.Email))
        {
            claims[OpenIddictConstants.Claims.Email] = (await _userManager.GetEmailAsync(user))!;
            claims[OpenIddictConstants.Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
        }

        if (User.HasScope(OpenIddictConstants.Permissions.Scopes.Phone))
        {
            claims[OpenIddictConstants.Claims.PhoneNumber] = (await _userManager.GetPhoneNumberAsync(user))!;
            claims[OpenIddictConstants.Claims.PhoneNumberVerified] =
                await _userManager.IsPhoneNumberConfirmedAsync(user);
        }

        if (User.HasScope(OpenIddictConstants.Permissions.Scopes.Roles))
        {
            claims[OpenIddictConstants.Claims.Role] = await _userManager.GetRolesAsync(user);
        }

        // Note: the complete list of standard claims supported by the OpenID Connect specification
        // can be found here: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

        return Ok(claims);
    }
}
