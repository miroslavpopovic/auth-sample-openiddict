using System.Linq.Expressions;
using Auth.Admin.Mappers;
using Auth.Admin.Models;
using Auth.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Auth.Admin.Pages.Applications;

public class IndexModel : PageModel
{
    private readonly ApplicationDbContext _dbContext;

    public IndexModel(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    [BindProperty]
    public IEnumerable<ApplicationModel> Applications { get; set; } = Array.Empty<ApplicationModel>();

    public int CurrentPage { get; set; }

    public int PageSize { get; set; }

    public string Search { get; set; } = string.Empty;

    public int TotalPages { get; set; }

    public async Task<IActionResult> OnGetAsync(string? search, int p = 1, int size = 10)
    {
        var dbSet = _dbContext.Set<OpenIddictEntityFrameworkCoreApplication>();

        Expression<Func<OpenIddictEntityFrameworkCoreApplication, bool>> searchExpression = x =>
            search == null ||
            (x.ClientId != null && x.ClientId.Contains(search)) ||
            (x.DisplayName != null && x.DisplayName.Contains(search));

        var applicationCount = await dbSet.CountAsync(searchExpression);

        var applications = await dbSet
            .Where(searchExpression)
            .Skip((p - 1) * size)
            .Take(size)
            .ToListAsync();

        Applications = applications.Select(ApplicationMappers.ToModel);
        CurrentPage = p;
        PageSize = size;
        Search = search ?? string.Empty;
        TotalPages = (int)Math.Ceiling((decimal)applicationCount / PageSize);

        return Page();
    }
}
