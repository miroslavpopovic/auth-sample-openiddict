namespace Samples.WeatherApi.WorkerClient;

public class Worker : BackgroundService
{
    private readonly HttpClient _regularHttpClient;
    private readonly IWeatherForecastClient _weatherForecastClient;
    private readonly ILogger<Worker> _logger;

    public Worker(
        IHttpClientFactory factory, IWeatherForecastClient weatherForecastClient, ILogger<Worker> logger)
    {
        _regularHttpClient = factory.CreateClient("weather-api-client");
        _weatherForecastClient = weatherForecastClient;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            _logger.LogInformation("Worker running at: {Time}", DateTimeOffset.Now);

            var stringResponse = await _regularHttpClient.GetStringAsync("weatherforecast", stoppingToken);
            _logger.LogInformation("Weather API response using regular HTTP client:\n{Response}", stringResponse);

            var weatherForecasts =
                (await _weatherForecastClient.GetWeatherForecastAsync()).ToArray();

            _logger.LogInformation(
                "Downloaded {Length} forecasts; max temp: {MaxTemp}, min temp: {MinTemp}",
                weatherForecasts.Length,
                weatherForecasts.Max(x => x.TemperatureC),
                weatherForecasts.Min(x => x.TemperatureC));

            await Task.Delay(3000, stoppingToken);
        }
    }
}
