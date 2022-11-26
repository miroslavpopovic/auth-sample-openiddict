using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Samples.WeatherSummaryApi.Controllers;

[ApiController]
[Route("[controller]")]
public class WeatherSummaryController : ControllerBase
{
    private readonly HttpClient _client;

    public WeatherSummaryController(IHttpClientFactory clientFactory)
    {
        _client = clientFactory.CreateClient("weather-api-client");
    }

    [HttpGet]
    public async Task<ActionResult<WeatherSummary>> Get()
    {
        // This is using an existing access_token, to also call another API
        // It needs to include another API scope too

        var authorizationHeader = HttpContext.Request.Headers["Authorization"];

        if (authorizationHeader.Count == 0 || authorizationHeader[0] == null)
        {
            return Unauthorized();
        }

        var accessToken = authorizationHeader[0]!.Replace("Bearer ", string.Empty);

        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        var content = await _client.GetStringAsync(string.Empty);

        var forecasts = JsonSerializer.Deserialize<IEnumerable<WeatherForecast>>(
            content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        return new WeatherSummary { Forecasts = forecasts! };
    }
}
