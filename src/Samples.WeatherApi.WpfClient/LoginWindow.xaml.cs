using IdentityModel;
using IdentityModel.Client;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media.Imaging;

namespace Samples.WeatherApi.WpfClient;

/// <summary>
/// Interaction logic for LoginWindow.xaml
/// </summary>
public partial class LoginWindow
{
    private static readonly IDiscoveryCache Cache =
        new DiscoveryCache(Constants.AuthUrl, DangerousHttpClientFactory.Create);
    private DeviceAuthorizationResponse _authorizationResponse = new();

    public LoginWindow() => InitializeComponent();

    public string AccessToken { get; private set; } = string.Empty;
    public string ErrorMessage { get; private set; } = string.Empty;

    private void CloseWithError(string error)
    {
        ErrorMessage = error;
        DialogResult = false;
        Close();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        var disco = await Cache.GetAsync();

        if (disco.IsError)
        {
            CloseWithError(disco.Error!);
            return;
        }

        var client = DangerousHttpClientFactory.Create();

        _authorizationResponse = await client.RequestDeviceAuthorizationAsync(
            new DeviceAuthorizationRequest
            {
                Address = disco.DeviceAuthorizationEndpoint,
                Scope = Constants.Scope,
                ClientId = Constants.ClientId
            });

        if (_authorizationResponse.IsError)
        {
            CloseWithError(_authorizationResponse.Error!);
            return;
        }

        var hyperlink = new Hyperlink(new Run(_authorizationResponse.VerificationUri));
        hyperlink.Click += (_, _) =>
        {
            Process.Start(
                new ProcessStartInfo
                {
                    FileName = _authorizationResponse.VerificationUri,
                    UseShellExecute = true
                });
        };

        UrlTextBlock.Content = hyperlink;
        UserCodeLabel.Content = _authorizationResponse.UserCode;

        var qrCodeUrl = string.Format(
            Constants.QrCodeUrlFormat, Uri.EscapeDataString(_authorizationResponse.VerificationUri!));
        QrCodeImage.Source = new BitmapImage(new Uri(qrCodeUrl));
    }

    private async void OnRequestTokenClick(object sender, RoutedEventArgs e)
    {
        RequestTokenButton.IsEnabled = false;
        CancelButton.IsEnabled = false;
        InformationTextBlock.Visibility = Visibility.Visible;

        var disco = await Cache.GetAsync();

        if (disco.IsError)
        {
            CloseWithError(disco.Error!);
            return;
        }

        var client = DangerousHttpClientFactory.Create();

        while (true)
        {
            var response = await client.RequestDeviceTokenAsync(new DeviceTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = Constants.ClientId,
                DeviceCode = _authorizationResponse.DeviceCode!
            });

            if (response.IsError)
            {
                if (response.Error == OidcConstants.TokenErrors.AuthorizationPending || response.Error == OidcConstants.TokenErrors.SlowDown)
                {
                    await Task.Delay(_authorizationResponse.Interval * 1000);
                }
                else
                {
                    CloseWithError(response.Error!);
                    return;
                }
            }
            else
            {
                AccessToken = response.AccessToken!;
                DialogResult = true;
                Close();
                return;
            }
        }
    }

    private void OnUserCodeDoubleClick(object sender, MouseButtonEventArgs e)
    {
        Clipboard.SetText(UserCodeLabel.Content.ToString() ?? string.Empty);
    }
}
