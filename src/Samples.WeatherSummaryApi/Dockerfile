#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["src/Samples.WeatherSummaryApi/Samples.WeatherSummaryApi.csproj", "src/Samples.WeatherSummaryApi/"]
RUN dotnet restore "src/Samples.WeatherSummaryApi/Samples.WeatherSummaryApi.csproj"
COPY . .
WORKDIR "/src/src/Samples.WeatherSummaryApi"
RUN dotnet build "Samples.WeatherSummaryApi.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Samples.WeatherSummaryApi.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Samples.WeatherSummaryApi.dll"]
