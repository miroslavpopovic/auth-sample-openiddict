using Auth.Admin.Mappers;
using Auth.Admin.Models;
using Auth.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.EntityFrameworkCore.Models;

namespace Auth.Admin.Pages.Scopes;

public class EditModel : PageModel
{
    private readonly ApplicationDbContext _dbContext;

    public string? Id { get; set; }

    [BindProperty]
    public ScopeModel Scope { get; set; } = new();

    public EditModel(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<IActionResult> OnGetAsync(string? id)
    {
        Id = id;

        if (string.IsNullOrWhiteSpace(id))
        {
            Scope = new ScopeModel();
        }
        else
        {
            var dbSet = _dbContext.Set<OpenIddictEntityFrameworkCoreScope>();
            var apiScope = await dbSet.FindAsync(id);

            if (apiScope == null)
            {
                return NotFound();
            }

            Scope = apiScope.ToModel();
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        OpenIddictEntityFrameworkCoreScope apiScope;
        var isNew = string.IsNullOrWhiteSpace(Scope.Id);

        var dbSet = _dbContext.Set<OpenIddictEntityFrameworkCoreScope>();
        if (isNew)
        {
            apiScope = Scope.ToEntity();
            await dbSet.AddAsync(apiScope);
        }
        else
        {
            apiScope = (await dbSet.FindAsync(Scope.Id))!;
            Scope.ToEntity(apiScope);
        }

        await _dbContext.SaveChangesAsync();

        return isNew
            ? RedirectToPage("/Scopes/Edit", new { id = apiScope.Id })
            : RedirectToPage("/Scopes/Index");
    }
}
