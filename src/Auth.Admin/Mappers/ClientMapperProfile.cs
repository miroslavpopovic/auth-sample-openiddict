using Auth.Admin.Extensions;
using Auth.Admin.Models;
using AutoMapper;
using Duende.IdentityServer.EntityFramework.Entities;

namespace Auth.Admin.Mappers;

public class ClientMapperProfile : Profile
{
    public ClientMapperProfile()
    {
        CreateMap<Client, ClientModel>(MemberList.Destination)
            .ReverseMap()
            .ForMember(
                x => x.RedirectUris,
                o => o.MapFrom(x => x.RedirectUris.ToList<ClientRedirectUri>(item => item.RedirectUri)))
            .ForMember(
                x => x.PostLogoutRedirectUris,
                o => o.MapFrom(
                    x => x.PostLogoutRedirectUris.ToList<ClientPostLogoutRedirectUri>(
                        item => item.PostLogoutRedirectUri)))
            .ForMember(
                x => x.AllowedCorsOrigins,
                o => o.MapFrom(x => x.AllowedCorsOrigins.ToList<ClientCorsOrigin>(item => item.Origin)));


        CreateMap<ClientGrantType, string>()
            .ConstructUsing(src => src.GrantType)
            .ReverseMap()
            .ForMember(dest => dest.GrantType, opt => opt.MapFrom(src => src));

        CreateMap<List<ClientRedirectUri>, string>()
            .ConstructUsing(src => string.Join(Environment.NewLine, src.Select(u => u.RedirectUri)))
            .ReverseMap();

        CreateMap<List<ClientPostLogoutRedirectUri>, string>()
            .ConstructUsing(src => string.Join(Environment.NewLine, src.Select(u => u.PostLogoutRedirectUri)))
            .ReverseMap();

        CreateMap<List<ClientIdPRestriction>, string>()
            .ConstructUsing(src => string.Join(Environment.NewLine, src.Select(u => u.Provider)))
            .ReverseMap();

        CreateMap<List<ClientCorsOrigin>, string>()
            .ConstructUsing(src => string.Join(Environment.NewLine, src.Select(u => u.Origin)))
            .ReverseMap();

        CreateMap<ClientScope, string>()
            .ConstructUsing(src => src.Scope)
            .ReverseMap()
            .ForMember(dest => dest.Scope, opt => opt.MapFrom(src => src));

        CreateMap<ClientSecret, ClientSecretModel>(MemberList.Destination)
            .ForMember(dest => dest.Type, opt => opt.Condition(srs => srs != null))
            .ReverseMap();

        CreateMap<ClientCorsOrigin, string>()
            .ConstructUsing(src => src.Origin)
            .ReverseMap()
            .ForMember(dest => dest.Origin, opt => opt.MapFrom(src => src));

        ////PagedLists
        //CreateMap<PagedList<ClientSecret>, ClientSecretsDto>(MemberList.Destination)
        //    .ForMember(x => x.ClientSecrets, opt => opt.MapFrom(src => src.Data));

        //CreateMap<PagedList<ClientClaim>, ClientClaimsDto>(MemberList.Destination)
        //    .ForMember(x => x.ClientClaims, opt => opt.MapFrom(src => src.Data));

        //CreateMap<PagedList<ClientProperty>, ClientPropertiesDto>(MemberList.Destination)
        //    .ForMember(x => x.ClientProperties, opt => opt.MapFrom(src => src.Data));

        //CreateMap<PagedList<Client>, ClientsDto>(MemberList.Destination)
        //    .ForMember(x => x.Clients, opt => opt.MapFrom(src => src.Data));
    }
}
