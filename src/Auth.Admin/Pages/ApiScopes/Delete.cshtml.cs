using Duende.IdentityServer.EntityFramework.DbContexts;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Auth.Admin.Pages.ApiScopes;

public class DeleteModel : PageModel
{
    private readonly ConfigurationDbContext _dbContext;

    public DeleteModel(ConfigurationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public string? Name { get; set; }

    [BindProperty]
    public int Id { get; set; }

    public async Task<IActionResult> OnGetAsync(int id)
    {
        var apiScope = await _dbContext.ApiScopes.FindAsync(id);

        if (apiScope == null)
        {
            return NotFound();
        }

        Id = id;
        Name = string.IsNullOrWhiteSpace(apiScope.DisplayName) ? apiScope.Name : apiScope.DisplayName;

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var apiScope = await _dbContext.ApiScopes.FindAsync(Id);

        if (apiScope == null)
        {
            return NotFound();
        }

        _dbContext.ApiScopes.Remove(apiScope);
        await _dbContext.SaveChangesAsync();

        return RedirectToPage("/ApiScopes/Index");
    }
}
