using Duende.AccessTokenManagement;
using Polly;
using Samples.WeatherApi.WorkerClient;

IHost host = Host.CreateDefaultBuilder(args)
    .ConfigureServices(services =>
    {
        // Default cache
        services.AddDistributedMemoryCache();

        // Configure access token management services with retry logic
        services
            .AddClientCredentialsTokenManagement()
            .AddClient("auth", client =>
            {
                client.TokenEndpoint = "https://localhost:7210/connect/token";
                client.ClientId = "weather-api-worker-client";
                client.ClientSecret = "secret";
                client.Scope = "weather-api";
            });

        var apiBaseUri = new Uri("https://localhost:7212/");

        services
            .AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .AcceptAnyServerCertificate()
            .AddTransientHttpErrorPolicy(
                policy => policy.WaitAndRetryAsync(
                    new[]
                    {
                        TimeSpan.FromSeconds(1),
                        TimeSpan.FromSeconds(2),
                        TimeSpan.FromSeconds(3)
                    }));

        services
            .AddClientCredentialsHttpClient("weather-api-client", "auth", client => client.BaseAddress = apiBaseUri)
            .AcceptAnyServerCertificate();

        services
            .AddHttpClient<IWeatherForecastClient, WeatherForecastClient>(client => client.BaseAddress = apiBaseUri)
            .AddClientCredentialsTokenHandler("auth")
            .AcceptAnyServerCertificate();

        services.AddHostedService<Worker>();
    })
    .Build();

await host.RunAsync();
