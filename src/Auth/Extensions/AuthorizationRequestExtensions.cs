using Duende.IdentityServer.Models;

namespace Auth.Extensions;

public static class AuthorizationRequestExtensions
{
    public static bool IsNativeClient(this AuthorizationRequest context)
    {
        return !context.RedirectUri.StartsWith("https", StringComparison.Ordinal)
           && !context.RedirectUri.StartsWith("http", StringComparison.Ordinal);
    }
}
