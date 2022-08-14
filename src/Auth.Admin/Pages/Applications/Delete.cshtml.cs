using Auth.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.EntityFrameworkCore.Models;

namespace Auth.Admin.Pages.Applications;

public class DeleteModel : PageModel
{
    private readonly ApplicationDbContext _dbContext;

    public DeleteModel(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public string ClientId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;

    [BindProperty]
    public string Id { get; set; } = string.Empty;

    public async Task<IActionResult> OnGetAsync(string id)
    {
        var dbSet = _dbContext.Set<OpenIddictEntityFrameworkCoreApplication>();

        var application = await dbSet.FindAsync(id);

        if (application == null)
        {
            return NotFound();
        }

        Id = id;
        ClientId = application.ClientId ?? string.Empty;
        DisplayName = application.DisplayName ?? string.Empty;

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var dbSet = _dbContext.Set<OpenIddictEntityFrameworkCoreApplication>();

        var application = await dbSet.FindAsync(Id);

        if (application == null)
        {
            return NotFound();
        }

        dbSet.Remove(application);
        await _dbContext.SaveChangesAsync();

        return RedirectToPage("/Applications/Index");
    }
}
