using System.ComponentModel.DataAnnotations;

namespace Auth.Admin.Models;

public class ApiScopeModel
{
    public int Id { get; set; }

    [Required]
    public string Name { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public bool Required { get; set; }
    public bool Emphasize { get; set; }
    public bool Enabled { get; set; }
}
