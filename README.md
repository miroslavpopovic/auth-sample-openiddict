# Auth microservice sample with OpenIddict

This is an alternative implementation of [auth microservice sample](https://github.com/miroslavpopovic/auth-microservice-sample-dotnet6) using OpenIddict instead of Duende Identity Server. This sample is written in .NET 6, using C# 10 and the latest OpenIddict.

As everyone is not able to fulfill the [pricing](https://duendesoftware.com/products/identityserver#pricing) or licensing requirements of Duende Identity Server (or do not want to), this sample gives an alternative by using [OpenIddict](https://github.com/openiddict/openiddict-core) instead of Duende IdentityServer.

[IdentityModel](https://github.com/IdentityModel/IdentityModel) is used for discovery, token validation, access token management, etc. Alternatively, [OpenIddict client](https://kevinchalet.com/2022/02/25/introducing-the-openiddict-client/) could be used instead, once it is released.

Note that the JavaScriptBffClient sample is using [Duende.Bff]() library, so it is a kind of a cheat. There is no alternative utility available for OpenIddict. However, you can check out [this sample](https://github.com/damienbod/AspNetCoreOpeniddict) by Damien Bowden that includes Blazor BFF setup using OpenIddict and [Yarp](https://microsoft.github.io/reverse-proxy/).

For any other type of samples, check out official [OpenIddict samples repository](https://github.com/openiddict/openiddict-samples).

## Projects

### Auth

This is the main project, containing both ASP.NET Core Identity and OpenIddict implementation, working together to create a single authentication/authorization service. This project was created using the Web Application template (with Razor Pages) and the following things done after that:

- Scaffolding page for 2FA authenticator app - modified to display qrCode
- Scaffolding page for managing user profile and changing profile image
- Custom `AuthUser` class with `ProfileImageName` property - inherited from `IdentityUser`
- Custom `ApplicationDbContext`, inherited from `IdentityDbContext` and registered through DI, since we have a new user class
- Custom `IEmailSender` implementation with [MimeKit](http://www.mimekit.net/)

The next thing was adding and configuring OpenIddict, by following [documentation](https://documentation.openiddict.com/) and [samples](https://github.com/openiddict/openiddict-samples/).

### Auth.Admin

An ASP.NET Core application that contains administration for OpenIddict clients and scopes, which are saved to SQL Server database. This project is heavily influenced by [Skoruba.DuendeIdentityServer.Admin project](https://github.com/skoruba/Duende.IdentityServer.Admin).

### WeatherApi and WeatherSummaryApi

ASP.NET Core API projects (resources), that clients are connecting to. WeatherSummaryApi demonstrates accessing one API from another.

### ConsoleClient

A .NET console application client for WeatherApi. Demonstrates a simple usage of [IdentityModel](https://github.com/IdentityModel).

### WorkerClient

A .NET worker service client for WeatherApi. Demonstrates the usage of IdentityModel's `AccessTokenManagement`, `HttpClientFactory` and strongly-typed `HttpClient`.

### MvcClient

An ASP.NET Core application which demonstrates several different ways of using access tokens to access protected resources (APIs).

### JavaScriptBffClient

*TODO:* See if this can be easily rewritten to use OpenIddict, or simply point to https://github.com/damienbod/AspNetCoreOpeniddict.

A combination of ASP.NET Core backend and JavaScript frontend app demonstrating usage of [BFF Security Framework](https://docs.duendesoftware.com/identityserver/v5/bff/). Note that this approach is [recommended for browser based apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps). Another approach would be to do all the security interactions on client-side code, which ends in more complex JavaScript and considerably higher attach surface. It is discouraged for applications dealing with sensitive data. Read more about it in [Duende IdentityServer documentation](https://docs.duendesoftware.com/identityserver/v5/quickstarts/js_clients/).

### WpfClient

A .NET Core WPF application demonstrating another usage of IdentityModel, as well as the device flow. It simulates the device without browser (i.e. Smart TV or gaming console) and displays link, code and QR code for device flow auth.

## Preparing

This solution requires .NET 6.0 SDK or higher.

### Database connection strings

If you are running the project with Project Tye or `docker-compose` (see below), SQL Server will be served as a Docker container and you don't need to install anything else (other than Docker itself).

However, if running via IISExpress or Kestrel, the default connection string, defined in `appsettings.json` file of both Auth and Auth.Admin projects, assumes that you have SQL Server installed locally, as the default (non-named) instance, and that you will be using `AuthOpenIddict` as the database. If you have a named instance of SQL Server, or a non-local instance, or need to use another database name, override the setting in the user secrets for both projects:

```json
"ConnectionStrings": {
  "auth-db": "Server=.;Database=AuthOpenIddict;Trusted_Connection=True;MultipleActiveResultSets=true"
}
```

### Google Demo external providers

You also need to modify the user secrets for `Auth` project. It should look like this (provide correct [client id and client secret](https://console.cloud.google.com/apis/credentials) for Google auth):

```json
{
  "Providers": {
    "Google": {
      "ClientId": "<google_app_client_id>",
      "ClientSecret": "<google_app_client_secret>"
    }
  }
}
```

Alternatively, just remove Google auth from `Startup` class of Auth project.

### Email sending

If you running via IISExpress or Kestrel, and want to have email sending working, you either need to have a local SMTP server, or modify the SMTP settings in `appsettings.json` file of Auth project. The easiest way to have local SMTP server is to use [smtp4dev](https://github.com/rnwood/smtp4dev). Install it with:

```shell
dotnet tool install -g Rnwood.Smtp4dev
```

Then run it with:

```shell
smtp4dev
```

It will now capture all emails sent from Auth project. You can see them on https://localhost:5001/.

If you are running your app with Project Tye or `docker-compose`, you'll have [MailHog](https://github.com/mailhog/MailHog) started as a service instead. The user interface is available at http://localhost:8025/.

## Running the solution

This solution is created to be as flexible as possible, by not imposing one way to run it. It can be run from command line, from Visual Studio, using the `docker-compose`, etc. However, the most easier way to run it is with Microsoft Project Tye.

### Using Project Tye

The purpose of Project Tye is to help with development and deployment of .NET microservice solutions. It is still in preview mode, so you can run into some missing pieces. I.e. a user friendly debugging story and integration with IDEs is not yet done. You can find more info in [project documentation on GitHub](https://github.com/dotnet/tye/tree/master/docs).

First, install the [latest version](https://www.nuget.org/packages/Microsoft.Tye) of Project Tye

```shell
dotnet tool install --global Microsoft.Tye --version <version>
```

Then you can just run Project Tye from the root of the repository.

```shell
tye run
```

It will run all the projects and services defined in `./tye.yaml` and serve a dashboard on http://localhost:8000/. From the Tye Dashboard, you can see all running services, open URLs in browser, view logs, etc.

### Using Kestrel or IISExpress

*Note: The solution contains multiple web projects, configured to run on specific ports. HTTPS addresses with ports are hard-coded throughout the code, for auth URLs and. The same ports are configured for both IISExpress and Kestrel, so you can use either.*

If using Visual Studio 2019+, you can open `Auth.sln` solution. To run multiple projects, right click on the solution in Solution Explorer and choose "Set StartUp Projects...". Select "Multiple" and pick the ones you want to start.

If running from the command line, you can start the projects you need from the root folder, with:

```shell
dotnet run --project src\Auth\Auth.csproj
dotnet run --project src\Auth.Admin\Auth.Admin.csproj
dotnet run --project src\Samples.WeatherApi\Samples.WeatherApi.csproj
dotnet run --project src\Samples.WeatherSummaryApi\Samples.WeatherSummaryApi.csproj
dotnet run --project src\Samples.WeatherApi.JavaScriptBffClient\Samples.WeatherApi.JavaScriptBffClient.csproj
dotnet run --project src\Samples.WeatherApi.ConsoleClient\Samples.WeatherApi.ConsoleClient.csproj
dotnet run --project src\Samples.WeatherApi.MvcClient\Samples.WeatherApi.MvcClient.csproj
dotnet run --project src\Samples.WeatherApi.WorkerClient\Samples.WeatherApi.WorkerClient.csproj
dotnet run --project src\Samples.WeatherApi.WpfClient\Samples.WeatherApi.WpfClient.csproj
```

If on Windows, there's a convenient PowerShell script to run all web projects at once:

```shell
.\run-web-projects.ps1
```

### Using Docker

The solution is ready to run with Docker too. It has `Dockerfile` files for each web project and `docker-compose.yml` and `docker-compose.override.yml` scripts for running all web projects.

Depending on your machine setup, you might need to create or export a dev certificate:

```shell
dotnet dev-certs https -ep %USERPROFILE%\.aspnet\https\aspnetapp.pfx -p password
dotnet dev-certs https --trust
```

While running all projects and communication between them was easy without Docker since we were using same `localhost`. Running in Docker is a bit tricky since we basically have multiple machines involved and each has its own `localhost` DNS entry. We can use internal Docker network, and refer to each machine through its DNS name, assigned by Docker Compose, but that would work only for machine to machine communication. When we add browser on the host to the mix, things start to fall apart. I.e. if we use `htpps://auth` as Authority in `auth-admin`, it will successfully retrieve OIDC config file, but will redirect the host browser to that address too, for login, and browser will fail, since host is not the part of the same network.

There are multiple ways this can be solved. For instance, we could configure the Docker Compose to use the host network, or we could use `host.docker.internal` DNS entry that Docker Compose creates in Windows `hosts` file (points to the current local IP address of the host), or we could modify DNS entries, etc.

The way it is solved in this repository is by defining a new DNS entry (similar to `host.docker.internal`) in `c:\Windows\system32\drivers\etc\hosts`. That host entry is named `auth.sample.local`. You can (and should) make sure that the entry exists in `hosts` file before running `docker-compose`. This is partially automated. Just run the **`update-hosts-entry.ps1`** script from the repository root as an admin. It will pick up your current local IP address and create or update the entry in `hosts` file. Note that this works on Windows too. For Linux or Mac, it's even simpler. Just add/update the entry in `/etc/hosts` file.

All web projects have `appsettings.Docker.json` files with settings overrides for Docker environment.

To run everything, either run `docker-compose` project from Visual Studio, or run `docker-compose up` from the command line.

## Upgrading to the latest OpenIddict

Check the migration guides on https://documentation.openiddict.com/guides/index.html.

The upgrade usually means that the database needs a schema upgrade. To upgrade the database schema, run the following from the command line:

```shell
cd ./src/Auth
dotnet ef migrations add UpgradeToLatestOpenIddict --output-dir ./Data/Migrations

# if there are upgrades, run the database update operation
dotnet ef database update
```

## License

See [LICENSE](LICENSE) file.
