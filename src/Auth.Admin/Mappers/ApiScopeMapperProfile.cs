using Auth.Admin.Models;
using AutoMapper;
using Duende.IdentityServer.EntityFramework.Entities;

namespace Auth.Admin.Mappers;

public class ApiScopeMapperProfile : Profile
{
    public ApiScopeMapperProfile()
    {
        CreateMap<ApiScope, ApiScopeModel>(MemberList.Destination);

        CreateMap<ApiScopeModel, ApiScope>(MemberList.Source);
    }
}
