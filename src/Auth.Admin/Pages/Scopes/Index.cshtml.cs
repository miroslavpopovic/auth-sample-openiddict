using Auth.Admin.Mappers;
using Auth.Admin.Models;
using Auth.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Auth.Admin.Pages.Scopes;

public class IndexModel : PageModel
{
    private readonly ApplicationDbContext _dbContext;

    [BindProperty]
    public IEnumerable<ScopeModel> Scopes { get; set; } = Array.Empty<ScopeModel>();

    public IndexModel(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        var dbSet = _dbContext.Set<OpenIddictEntityFrameworkCoreScope>();
        var apiScopes = await dbSet.ToListAsync();

        Scopes = apiScopes.Select(ScopeMappers.ToModel);

        return Page();
    }
}
