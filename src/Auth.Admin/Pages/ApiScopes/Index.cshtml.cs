using Auth.Admin.Mappers;
using Auth.Admin.Models;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Auth.Admin.Pages.ApiScopes;

public class IndexModel : PageModel
{
    private readonly ConfigurationDbContext _dbContext;

    [BindProperty]
    public IEnumerable<ApiScopeModel> ApiScopes { get; set; } = Array.Empty<ApiScopeModel>();

    public IndexModel(ConfigurationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        var apiScopes = await _dbContext.ApiScopes.ToListAsync();

        ApiScopes = apiScopes.Select(ApiScopeMappers.ToModel);

        return Page();
    }
}
