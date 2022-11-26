// See https://aka.ms/new-console-template for more information

using IdentityModel.Client;
using System.Text.Json;
using Samples.WeatherApi.ConsoleClient;

var client = DangerousHttpClientFactory.Create();

var disco = await client.GetDiscoveryDocumentAsync("https://localhost:7210");
if (disco.IsError)
{
    Console.WriteLine(disco.Error);
    return;
}

// request token
var tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
{
    Address = disco.TokenEndpoint,
    ClientId = "weather-api-console-client",
    ClientSecret = "secret",

    Scope = "weather-api"
});

if (tokenResponse.IsError)
{
    Console.WriteLine(tokenResponse.Error);
    return;
}

Console.WriteLine(tokenResponse.Json);
Console.WriteLine("\n\n");

// call api
var apiClient = DangerousHttpClientFactory.Create();
apiClient.SetBearerToken(tokenResponse.AccessToken);

var response = await apiClient.GetAsync("https://localhost:7212/weatherforecast");
if (!response.IsSuccessStatusCode)
{
    Console.WriteLine(response.StatusCode);
}
else
{
    var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
    Console.WriteLine(JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true }));
}

