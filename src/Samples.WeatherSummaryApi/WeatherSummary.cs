namespace Samples.WeatherSummaryApi
{
    public class WeatherSummary
    {
        public IEnumerable<WeatherForecast> Forecasts { get; set; } = Array.Empty<WeatherForecast>();

        public int MaxTemperatureC => Forecasts.Max(x => x.TemperatureC);

        public int MinTemperatureC => Forecasts.Min(x => x.TemperatureC);
    }
}
