using Microsoft.Build.Framework;

namespace Auth.Admin.Models;

public class ScopeModel
{
    public string? Id { get; set; } = string.Empty;

    public string? ConcurrencyToken { get; set; }

    public string? Description { get; set; }

    public string? DisplayName { get; set; }

    [Required]
    public string Name { get; set; } = string.Empty;
}
