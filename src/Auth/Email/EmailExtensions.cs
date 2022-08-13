using Microsoft.AspNetCore.Identity.UI.Services;

namespace Auth.Email;

public static class EmailExtensions
{
    public static void AddEmail(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<EmailOptions>(configuration.GetSection("Email"));
        services.AddTransient<IEmailSender, EmailSender>();
    }
}
