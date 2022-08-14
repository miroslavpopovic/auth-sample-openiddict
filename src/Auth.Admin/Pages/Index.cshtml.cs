using Auth.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Auth.Admin.Pages;

public class IndexModel : PageModel
{
    private readonly ApplicationDbContext _dbContext;

    public IndexModel(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public int ApplicationCount { get; set; }
    public int ScopeCount { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        ApplicationCount = await _dbContext.Set<OpenIddictEntityFrameworkCoreApplication>().CountAsync();
        ScopeCount = await _dbContext.Set<OpenIddictEntityFrameworkCoreScope>().CountAsync();

        return Page();
    }

    public IActionResult OnGetLogout()
    {
        return SignOut(
            CookieAuthenticationDefaults.AuthenticationScheme,
            OpenIdConnectDefaults.AuthenticationScheme);
    }
}
