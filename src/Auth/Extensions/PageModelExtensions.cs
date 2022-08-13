using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Auth.Extensions;

public static class PageModelExtensions
{
    public static IActionResult LoadingPage(this PageModel pageModel, string pageName, string redirectUri)
    {
        return pageModel.RedirectToPage(pageName, new { redirectUri });
    }
}
