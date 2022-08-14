using Auth.Admin.Models;
using AutoMapper;
using OpenIddict.EntityFrameworkCore.Models;

namespace Auth.Admin.Mappers;

public static class ApplicationMappers
{
    static ApplicationMappers()
    {
        Mapper = new MapperConfiguration(cfg => cfg.AddProfile<ApplicationMapperProfile>())
            .CreateMapper();
    }

    private static IMapper Mapper { get; }

    public static OpenIddictEntityFrameworkCoreApplication ToEntity(this ApplicationModel model) =>
        Mapper.Map<OpenIddictEntityFrameworkCoreApplication>(model);

    public static void ToEntity(this ApplicationModel model, OpenIddictEntityFrameworkCoreApplication application) =>
        Mapper.Map(model, application);

    public static ApplicationModel ToModel(this OpenIddictEntityFrameworkCoreApplication application) =>
        Mapper.Map<ApplicationModel>(application);
}
