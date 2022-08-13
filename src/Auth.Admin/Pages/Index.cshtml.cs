using Duende.IdentityServer.EntityFramework.DbContexts;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Auth.Admin.Pages;

public class IndexModel : PageModel
{
    private readonly ConfigurationDbContext _dbContext;

    public IndexModel(ConfigurationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public int ClientCount { get; set; }
    public int ApiScopesCount { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        ClientCount = await _dbContext.Clients.CountAsync();
        ApiScopesCount = await _dbContext.ApiScopes.CountAsync();

        return Page();
    }

    public IActionResult OnGetLogout()
    {
        return SignOut(
            CookieAuthenticationDefaults.AuthenticationScheme,
            OpenIdConnectDefaults.AuthenticationScheme);
    }
}
