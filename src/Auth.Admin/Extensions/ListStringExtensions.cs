using System.Linq.Expressions;
using System.Reflection;

namespace Auth.Admin.Extensions;

public static class ListStringExtensions
{
    public static List<T> ToList<T>(this string? value, Expression<Func<T, string>> property) where T : new()
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return new List<T>();
        }

        return value.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
            .Select(x =>
            {
                var item = new T();
                SetPropertyValue(item, property, x);
                return item;
            })
            .ToList();
    }

    private static void SetPropertyValue<T, TValue>(T target, Expression<Func<T, TValue>> memberLambda, TValue value)
    {
        if (!(memberLambda.Body is MemberExpression memberSelectorExpression)) return;

        var property = memberSelectorExpression.Member as PropertyInfo;

        if (property != null)
        {
            property.SetValue(target, value, null);
        }
    }
}
