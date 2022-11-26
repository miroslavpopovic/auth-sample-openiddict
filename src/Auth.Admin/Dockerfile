#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["src/Auth.Admin/Auth.Admin.csproj", "src/Auth.Admin/"]
RUN dotnet restore "src/Auth.Admin/Auth.Admin.csproj"
COPY . .
WORKDIR "/src/src/Auth.Admin"
RUN dotnet build "Auth.Admin.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Auth.Admin.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Auth.Admin.dll"]
