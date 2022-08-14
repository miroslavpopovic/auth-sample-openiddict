using Auth.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.EntityFrameworkCore.Models;

namespace Auth.Admin.Pages.Scopes;

public class DeleteModel : PageModel
{
    private readonly ApplicationDbContext _dbContext;

    public DeleteModel(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public string? Name { get; set; }

    [BindProperty]
    public string Id { get; set; } = string.Empty;

    public async Task<IActionResult> OnGetAsync(string id)
    {
        var dbSet = _dbContext.Set<OpenIddictEntityFrameworkCoreScope>();
        var scope = await dbSet.FindAsync(id);

        if (scope == null)
        {
            return NotFound();
        }

        Id = id;
        Name = string.IsNullOrWhiteSpace(scope.DisplayName) ? scope.Name : scope.DisplayName;

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var dbSet = _dbContext.Set<OpenIddictEntityFrameworkCoreScope>();
        var scope = await dbSet.FindAsync(Id);

        if (scope == null)
        {
            return NotFound();
        }

        dbSet.Remove(scope);
        await _dbContext.SaveChangesAsync();

        return RedirectToPage("/Scopes/Index");
    }
}
