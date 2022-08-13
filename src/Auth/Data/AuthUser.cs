using Microsoft.AspNetCore.Identity;

namespace Auth.Data;

public class AuthUser : IdentityUser
{
    public string ProfileImageName { get; set; } = string.Empty;
}

