FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY oauth2-auth-broker.slnx ./
COPY src/OAuth2AuthBroker/OAuth2AuthBroker.csproj src/OAuth2AuthBroker/
RUN dotnet restore src/OAuth2AuthBroker/OAuth2AuthBroker.csproj

COPY src/OAuth2AuthBroker/ src/OAuth2AuthBroker/
ARG FILE_VERSION
RUN dotnet publish src/OAuth2AuthBroker/OAuth2AuthBroker.csproj \
    --no-restore \
    -c Release \
    -o /app/publish \
    ${FILE_VERSION:+-p:FileVersion=${FILE_VERSION}}

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .

EXPOSE 8080
ENTRYPOINT ["dotnet", "OAuth2AuthBroker.dll"]
