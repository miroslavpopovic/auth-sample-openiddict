using Auth.Admin.Mappers;
using Auth.Admin.Models;
using Auth.Admin.Services;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Auth.Admin.Pages.ApiScopes;

public class EditModel : PageModel
{
    private readonly ConfigurationDbContext _dbContext;

    public int? Id { get; set; }

    [BindProperty]
    public ApiScopeModel ApiScope { get; set; } = new();

    public IEnumerable<string> Claims { get; set; } = Array.Empty<string>();

    public EditModel(ConfigurationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<IActionResult> OnGetAsync(int? id)
    {
        Id = id;

        if (!id.HasValue)
        {
            ApiScope = new ApiScopeModel();
        }
        else
        {
            var apiScope = await LoadApiScope(id);

            if (apiScope == null)
            {
                return NotFound();
            }

            ApiScope = apiScope.ToModel();
        }

        LoadLookups();

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            LoadLookups();
            return Page();
        }

        ApiScope apiScope;
        var isNew = ApiScope.Id == 0;

        if (isNew)
        {
            apiScope = ApiScope.ToEntity();
            await _dbContext.ApiScopes.AddAsync(apiScope);
        }
        else
        {
            apiScope = (await LoadApiScope(ApiScope.Id))!;
            ApiScope.ToEntity(apiScope);
        }

        await _dbContext.SaveChangesAsync();

        return isNew
            ? RedirectToPage("/ApiScopes/Edit", new { id = apiScope.Id })
            : RedirectToPage("/ApiScopes/Index");
    }

    private async Task<ApiScope?> LoadApiScope(int? id)
    {
        return await _dbContext.ApiScopes
            .Include(x => x.UserClaims)
            .SingleOrDefaultAsync(x => x.Id == id);
    }

    private void LoadLookups()
    {
        Claims = PredefinedData.GetClaimTypes();
    }
}
