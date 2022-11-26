using IdentityModel.Client;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using System.Windows;

namespace Samples.WeatherApi.WpfClient;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private string _accessToken = string.Empty;

    public MainWindow()
    {
        InitializeComponent();
    }

    private async void OnCallWeatherApiClick(object sender, RoutedEventArgs e)
    {
        var apiClient = DangerousHttpClientFactory.Create();

        if (!string.IsNullOrWhiteSpace(_accessToken))
        {
            apiClient.SetBearerToken(_accessToken);
        }

        var response = await apiClient.GetAsync(Constants.ApiUrl);

        if (!response.IsSuccessStatusCode)
        {
            ResponseTextBox.Text = $"Request failed: {response.StatusCode}\r\n{response.ReasonPhrase}";
        }
        else
        {
            var content = await response.Content.ReadAsStringAsync();
            ResponseTextBox.Text = JArray.Parse(content).ToString(Formatting.Indented);
        }
    }

    private void OnLoginClick(object sender, RoutedEventArgs e)
    {
        var loginWindow = new LoginWindow();

        if (loginWindow.ShowDialog() == true)
        {
            _accessToken = loginWindow.AccessToken;
            ResponseTextBox.Text = $"Logged in successfully, access token: {_accessToken}";
        }
        else
        {
            ResponseTextBox.Text = string.IsNullOrWhiteSpace(loginWindow.ErrorMessage)
                ? "Login cancelled"
                : loginWindow.ErrorMessage;
        }
    }
}
