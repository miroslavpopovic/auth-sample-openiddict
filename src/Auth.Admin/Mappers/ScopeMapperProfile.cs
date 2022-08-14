using Auth.Admin.Models;
using AutoMapper;
using OpenIddict.EntityFrameworkCore.Models;

namespace Auth.Admin.Mappers;

public class ScopeMapperProfile : Profile
{
    public ScopeMapperProfile()
    {
        CreateMap<OpenIddictEntityFrameworkCoreScope, ScopeModel>(MemberList.Destination);

        CreateMap<ScopeModel, OpenIddictEntityFrameworkCoreScope>(MemberList.Source);
    }
}
