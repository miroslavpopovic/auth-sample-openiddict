using Microsoft.Build.Framework;

namespace Auth.Admin.Models;

public class ApplicationModel
{
    public string? Id { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    public string? ClientSecret { get; set; }

    public string? ConsentType { get; set; }

    [Required]
    public string DisplayName { get; set; } = string.Empty;

    public string? Permissions { get; set; }

    public string? PostLogoutRedirectUris { get; set; }

    public string? RedirectUris { get; set; }
    public string? Requirements { get; set; }
    public string? Type { get; set; }
}
