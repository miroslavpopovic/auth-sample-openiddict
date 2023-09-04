using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Nodes;
using Duende.AccessTokenManagement.OpenIdConnect;
using IdentityModel.Client;

namespace Samples.WeatherApi.MvcClient.Controllers
{
    public class WeatherForecastController : Controller
    {
        private readonly IUserTokenManagementService _tokenManagementService;
        private readonly HttpClient _forecastClient;
        private readonly HttpClient _summaryClient;
        private readonly string _weatherForecastApiUrl;
        private readonly string _weatherSummaryApiUrl;

        public WeatherForecastController(
            IHttpClientFactory clientFactory, IConfiguration configuration,
            IUserTokenManagementService tokenManagementService)
        {
            _tokenManagementService = tokenManagementService;

            _weatherForecastApiUrl =
                $"{configuration.GetServiceUri("weather-api")}weatherforecast";
            _weatherSummaryApiUrl =
                $"{configuration.GetServiceUri("weather-summary-api")}weathersummary";

            _forecastClient = clientFactory.CreateClient("weather-api-client");
            _summaryClient = clientFactory.CreateClient("weather-summary-api-client");
        }

        public async Task<IActionResult> Index()
        {
            // This is using an existing access_token, used to authorize access to MVC app, to also call API
            // It needs to include API scope too

            var accessToken = await _tokenManagementService.GetAccessTokenAsync(User);

            var httpClientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };

            var client = new HttpClient(httpClientHandler);
            client.SetBearerToken(accessToken.AccessToken!);

            var content = await client.GetStringAsync(_weatherForecastApiUrl);

            ViewBag.WeatherForecastData = JsonNode.Parse(content)!.ToString();

            return View();
        }

        public async Task<IActionResult> Index2()
        {
            // This is using a separate API Client to get access token
            // for accessing Weather API using the Client Credentials

            var content = await _forecastClient.GetStringAsync(_weatherForecastApiUrl);

            ViewBag.WeatherForecastData = JsonNode.Parse(content)!.ToString();

            return View();
        }

        public async Task<IActionResult> Summary()
        {
            // This is using a separate API Client to get access token
            // for accessing Weather API using the Client Credentials

            var content = await _summaryClient.GetStringAsync(_weatherSummaryApiUrl);

            ViewBag.WeatherSummaryData = JsonNode.Parse(content)!.ToString();

            return View();
        }
    }
}
