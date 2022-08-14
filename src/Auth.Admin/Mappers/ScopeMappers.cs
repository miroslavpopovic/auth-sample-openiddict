using Auth.Admin.Models;
using AutoMapper;
using OpenIddict.EntityFrameworkCore.Models;

namespace Auth.Admin.Mappers;

public static class ScopeMappers
{
    static ScopeMappers()
    {
        Mapper = new MapperConfiguration(cfg => cfg.AddProfile<ScopeMapperProfile>())
            .CreateMapper();
    }

    private static IMapper Mapper { get; }

    public static ScopeModel ToModel(this OpenIddictEntityFrameworkCoreScope scope) =>
        Mapper.Map<ScopeModel>(scope);

    public static OpenIddictEntityFrameworkCoreScope ToEntity(this ScopeModel model) =>
        Mapper.Map<OpenIddictEntityFrameworkCoreScope>(model);

    public static void ToEntity(this ScopeModel model, OpenIddictEntityFrameworkCoreScope scope) =>
        Mapper.Map(model, scope);
}
