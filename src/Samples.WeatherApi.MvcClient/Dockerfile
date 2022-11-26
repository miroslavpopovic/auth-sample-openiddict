#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["src/Samples.WeatherApi.MvcClient/Samples.WeatherApi.MvcClient.csproj", "src/Samples.WeatherApi.MvcClient/"]
RUN dotnet restore "src/Samples.WeatherApi.MvcClient/Samples.WeatherApi.MvcClient.csproj"
COPY . .
WORKDIR "/src/src/Samples.WeatherApi.MvcClient"
RUN dotnet build "Samples.WeatherApi.MvcClient.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Samples.WeatherApi.MvcClient.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Samples.WeatherApi.MvcClient.dll"]
