using Auth.Admin.Models;
using AutoMapper;
using Duende.IdentityServer.EntityFramework.Entities;

namespace Auth.Admin.Mappers;

public static class ApiScopeMappers
{
    static ApiScopeMappers()
    {
        Mapper = new MapperConfiguration(cfg => cfg.AddProfile<ApiScopeMapperProfile>())
            .CreateMapper();
    }

    private static IMapper Mapper { get; }

    public static ApiScopeModel ToModel(this ApiScope scope)
    {
        return Mapper.Map<ApiScopeModel>(scope);
    }

    public static ApiScope ToEntity(this ApiScopeModel model)
    {
        return Mapper.Map<ApiScope>(model);
    }

    public static void ToEntity(this ApiScopeModel model, ApiScope apiScope)
    {
        Mapper.Map(model, apiScope);
    }
}
