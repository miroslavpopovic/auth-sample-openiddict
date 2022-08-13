using Microsoft.AspNetCore.Mvc.Rendering;

namespace Auth.Admin.Extensions;

public static class EnumExtensions
{
    public static IEnumerable<SelectListItem> ToSelectList<T>() where T : struct, IComparable
    {
        return Enum.GetValues(typeof(T))
            .Cast<T>()
            .Select(x => new SelectListItem(x.ToString(), Convert.ToInt16(x).ToString()));
    }
}
