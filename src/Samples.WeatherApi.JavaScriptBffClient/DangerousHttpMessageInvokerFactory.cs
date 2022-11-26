using System.Net;
using System.Net.Security;
using Duende.Bff.Yarp;

namespace Samples.WeatherApi.JavaScriptBffClient;

/// <summary>
/// A custom implementation of <see cref="IHttpMessageInvokerFactory"/> that allows for
/// the remote server certificate to be self-signed.
/// WARNING: However, this approves ANY KIND of certificate, not just self-signed, so it
/// should never be used in production!
/// </summary>
public class DangerousHttpMessageInvokerFactory : DefaultHttpMessageInvokerFactory
{
    protected override HttpMessageHandler CreateHandler(string localPath)
    {
        return new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            }
        };
    }
}
