using System.ComponentModel.DataAnnotations;

namespace Auth.Admin.Models;

public class ClientModel
{
    public ClientModel()
    {
        AllowedScopes = new List<string>();
        AllowedGrantTypes = new List<string>();
        ClientSecrets = new List<ClientSecretModel>();
    }

    public ClientType ClientType { get; set; }

    public int AbsoluteRefreshTokenLifetime { get; set; } = 2592000;
    public int AccessTokenLifetime { get; set; } = 3600;

    public bool AllowOfflineAccess { get; set; }
    public bool AlwaysIncludeUserClaimsInIdToken { get; set; }
    public bool AlwaysSendClientClaims { get; set; }

    public string? FrontChannelLogoutUri { get; set; }
    public bool FrontChannelLogoutSessionRequired { get; set; } = true;
    public string? BackChannelLogoutUri { get; set; }
    public bool BackChannelLogoutSessionRequired { get; set; } = true;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [Required]
    public string ClientName { get; set; } = string.Empty;

    public string? ClientUri { get; set; }

    public string Description { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;
    public int Id { get; set; }
    public string? LogoUri { get; set; }

    public int RefreshTokenExpiration { get; set; } = 1;

    public int RefreshTokenUsage { get; set; } = 1;

    public int SlidingRefreshTokenLifetime { get; set; } = 1296000;

    public bool RequireClientSecret { get; set; } = true;
    public bool RequireConsent { get; set; } = true;
    public bool RequirePkce { get; set; }

    public string? PostLogoutRedirectUris { get; set; }

    public string? RedirectUris { get; set; }

    public string? AllowedCorsOrigins { get; set; }

    public List<string> AllowedGrantTypes { get; set; }

    public List<string> AllowedScopes { get; set; }

    public List<ClientSecretModel> ClientSecrets { get; set; }

    public DateTime? Updated { get; set; }
    public DateTime? LastAccessed { get; set; }

    public int DeviceCodeLifetime { get; set; } = 300;
}
