using Auth.Admin.Models;
using AutoMapper;
using OpenIddict.EntityFrameworkCore.Models;

namespace Auth.Admin.Mappers;

public class ApplicationMapperProfile : Profile
{
    public ApplicationMapperProfile()
    {
        CreateMap<OpenIddictEntityFrameworkCoreApplication, ApplicationModel>(MemberList.Destination);
        CreateMap<ApplicationModel, OpenIddictEntityFrameworkCoreApplication>(MemberList.Source);
    }
}
