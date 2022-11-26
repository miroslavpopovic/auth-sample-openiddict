namespace Samples.WeatherApi.WorkerClient;

public static class DangerousHttpClientBuilderExtensions
{
    // ReSharper disable once UnusedMethodReturnValue.Global
    public static IHttpClientBuilder AcceptAnyServerCertificate(this IHttpClientBuilder builder) =>
        builder.ConfigurePrimaryHttpMessageHandler(
            () => new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            });
}
