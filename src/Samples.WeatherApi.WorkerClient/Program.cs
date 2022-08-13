using IdentityModel.Client;
using Polly;
using Samples.WeatherApi.WorkerClient;

IHost host = Host.CreateDefaultBuilder(args)
    .ConfigureServices(services =>
    {
        // Configure access token management services with retry logic
        // TODO: Replace this with Duende.AccessTokenManagement once it's out of the preview phase
        // https://blog.duendesoftware.com/posts/20220804_datm/
        services
            .AddAccessTokenManagement(
                options =>
                {
                    options.Client.Clients.Add(
                        "auth", new ClientCredentialsTokenRequest
                        {
                            Address = "https://localhost:7210/connect/token",
                            ClientId = "weather-api-worker-client",
                            ClientSecret = "secret",
                            Scope = "weather-api"
                        });
                })
            .ConfigureBackchannelHttpClient()
            .AddTransientHttpErrorPolicy(
                policy =>
                    policy.WaitAndRetryAsync(
                        new[]
                        {
                            TimeSpan.FromSeconds(1),
                            TimeSpan.FromSeconds(2),
                            TimeSpan.FromSeconds(3)
                        }));

        var apiBaseUri = new Uri("https://localhost:7212/");

        // Register regular HttpClient that knows how to handle tokens
        services.AddClientAccessTokenHttpClient(
            "weather-api-client",
            configureClient: client => { client.BaseAddress = apiBaseUri; });

        // Register strongly typed HttpClient
        services.AddHttpClient<IWeatherForecastClient, WeatherForecastClient>(
            client => { client.BaseAddress = apiBaseUri; })
            .AddClientAccessTokenHandler();

        services.AddHostedService<Worker>();
    })
    .Build();

await host.RunAsync();
