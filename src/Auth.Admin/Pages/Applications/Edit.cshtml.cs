using Auth.Admin.Mappers;
using Auth.Admin.Models;
using Auth.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.EntityFrameworkCore.Models;

namespace Auth.Admin.Pages.Applications;

public class EditModel : PageModel
{
    private readonly ApplicationDbContext _dbContext;

    public EditModel(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public string? Id { get; private set; }

    [BindProperty]
    public ApplicationModel Application { get; set; } = new();

    public async Task<IActionResult> OnGetAsync(string? id)
    {
        Id = id;

        if (string.IsNullOrWhiteSpace(id))
        {
            Application = new ApplicationModel();
        }
        else
        {
            var dbSet = _dbContext.Set<OpenIddictEntityFrameworkCoreApplication>();

            var application = await dbSet.FindAsync(id);

            if (application == null)
            {
                return NotFound();
            }

            Application = application.ToModel();
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        OpenIddictEntityFrameworkCoreApplication application;
        var isNew = string.IsNullOrWhiteSpace(Application.Id);

        var dbSet = _dbContext.Set<OpenIddictEntityFrameworkCoreApplication>();
        if (isNew)
        {
            application = Application.ToEntity();
            application.ConcurrencyToken = Guid.NewGuid().ToString();
            await dbSet.AddAsync(application);
        }
        else
        {
            application = (await dbSet.FindAsync(Application.Id))!;
            Application.ToEntity(application);
        }

        await _dbContext.SaveChangesAsync();

        return isNew
            ? RedirectToPage("/Applications/Edit", new {id = application.Id})
            : RedirectToPage("/Applications/Index");
    }
}
