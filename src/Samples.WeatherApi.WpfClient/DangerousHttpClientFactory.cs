using System.Net.Http;

namespace Samples.WeatherApi.WpfClient;

public static class DangerousHttpClientFactory
{
    public static HttpClient Create()
    {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;

        // Not a best way to create an HttpClient instance, check the official guidelines instead:
        // https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/http/httpclient-guidelines
        return new HttpClient(handler);
    }
}
