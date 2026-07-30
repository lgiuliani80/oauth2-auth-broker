using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Identity.Client;
using Microsoft.Extensions.Hosting;

namespace OAuth2AuthBroker.Tests.Integration;

public sealed class MsalOidcAuthorityTests
{
    [Fact]
    public async Task AcquireTokenForClient_WithOidcAuthority_FailsWhenMetadataIssuerDiffers()
    {
        const string authority = "https://mock.local/adfs";
        const string expectedAccessToken = "header.payload.signature";

        var metadataCalls = 0;
        var tokenCalls = 0;

        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.Configure(app =>
                {
                    app.Run(async context =>
                    {
                        var path = context.Request.Path.Value ?? string.Empty;

                        if (path.Equals("/adfs/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase))
                        {
                            metadataCalls++;
                            context.Response.StatusCode = (int)HttpStatusCode.OK;
                            context.Response.ContentType = "application/json";

                            var metadata = new
                            {
                                issuer = "https://issuer-does-not-match-authority.example.local",
                                token_endpoint = "https://mock.local/adfs/oauth2/token",
                                authorization_endpoint = "https://mock.local/adfs/oauth2/authorize"
                            };

                            await context.Response.WriteAsync(JsonSerializer.Serialize(metadata));
                            return;
                        }

                        if (path.Equals("/adfs/oauth2/token", StringComparison.OrdinalIgnoreCase))
                        {
                            tokenCalls++;

                            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
                            var formBody = await reader.ReadToEndAsync();
                            Assert.Contains("grant_type=client_credentials", formBody, StringComparison.Ordinal);
                            Assert.Contains("client_id=test-client-id", formBody, StringComparison.Ordinal);

                            context.Response.StatusCode = (int)HttpStatusCode.OK;
                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsync(
                                "{\"token_type\":\"Bearer\",\"expires_in\":3600,\"access_token\":\"" + expectedAccessToken + "\"}");
                            return;
                        }

                        context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                    });
                });
            })
            .StartAsync(CancellationToken.None);

        var server = host.GetTestServer();

        var app = ConfidentialClientApplicationBuilder
            .Create("test-client-id")
            .WithOidcAuthority(authority)
            .WithClientSecret("test-client-secret")
            .WithHttpClientFactory(new TestMsalHttpClientFactory(server))
            .Build();

        var ex = await Assert.ThrowsAsync<MsalServiceException>(async () =>
        {
            await app
                .AcquireTokenForClient(["api://target/.default"])
                .ExecuteAsync(CancellationToken.None);
        });

        Assert.Contains("Issuer validation failed", ex.Message, StringComparison.Ordinal);
        Assert.True(metadataCalls > 0);
        Assert.Equal(0, tokenCalls);
    }

    [Fact]
    public async Task AcquireTokenForClient_WithOidcAuthority_SucceedsWhenMetadataIssuerMatchesAuthority()
    {
        const string authority = "https://mock.local/adfs";
        const string expectedAccessToken = "header.payload.signature";

        var metadataCalls = 0;
        var tokenCalls = 0;

        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.Configure(app =>
                {
                    app.Run(async context =>
                    {
                        var path = context.Request.Path.Value ?? string.Empty;

                        if (path.Equals("/adfs/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase))
                        {
                            metadataCalls++;
                            context.Response.StatusCode = (int)HttpStatusCode.OK;
                            context.Response.ContentType = "application/json";

                            var metadata = new
                            {
                                issuer = authority,
                                token_endpoint = "https://mock.local/adfs/oauth2/token",
                                authorization_endpoint = "https://mock.local/adfs/oauth2/authorize"
                            };

                            await context.Response.WriteAsync(JsonSerializer.Serialize(metadata));
                            return;
                        }

                        if (path.Equals("/adfs/oauth2/token", StringComparison.OrdinalIgnoreCase))
                        {
                            tokenCalls++;

                            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
                            var formBody = await reader.ReadToEndAsync();
                            Assert.Contains("grant_type=client_credentials", formBody, StringComparison.Ordinal);
                            Assert.Contains("client_id=test-client-id", formBody, StringComparison.Ordinal);

                            context.Response.StatusCode = (int)HttpStatusCode.OK;
                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsync(
                                "{\"token_type\":\"Bearer\",\"expires_in\":3600,\"access_token\":\"" + expectedAccessToken + "\"}");
                            return;
                        }

                        context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                    });
                });
            })
            .StartAsync(CancellationToken.None);

        var server = host.GetTestServer();

        var app = ConfidentialClientApplicationBuilder
            .Create("test-client-id")
            .WithOidcAuthority(authority)
            .WithClientSecret("test-client-secret")
            .WithHttpClientFactory(new TestMsalHttpClientFactory(server))
            .Build();

        var result = await app
            .AcquireTokenForClient(["api://target/.default"])
            .ExecuteAsync(CancellationToken.None);

        Assert.Equal(expectedAccessToken, result.AccessToken);
        Assert.True(metadataCalls > 0);
        Assert.True(tokenCalls > 0);
    }

    [Fact]
    public async Task AcquireTokenForClient_WithOidcAuthority_SucceedsForAdfsLikeAuthorityPath()
    {
        const string authority = "https://mock.local/adfs/";
        const string metadataIssuer = "https://mock.local/adfs";
        const string expectedAccessToken = "adfs-like-token";

        var metadataCalls = 0;
        var tokenCalls = 0;

        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.Configure(app =>
                {
                    app.Run(async context =>
                    {
                        var path = context.Request.Path.Value ?? string.Empty;

                        if (path.Equals("/adfs/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase))
                        {
                            metadataCalls++;
                            context.Response.StatusCode = (int)HttpStatusCode.OK;
                            context.Response.ContentType = "application/json";

                            var metadata = new
                            {
                                issuer = metadataIssuer,
                                token_endpoint = "https://mock.local/adfs/oauth2/token",
                                authorization_endpoint = "https://mock.local/adfs/oauth2/authorize"
                            };

                            await context.Response.WriteAsync(JsonSerializer.Serialize(metadata));
                            return;
                        }

                        if (path.Equals("/adfs/oauth2/token", StringComparison.OrdinalIgnoreCase))
                        {
                            tokenCalls++;

                            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
                            var formBody = await reader.ReadToEndAsync();
                            Assert.Contains("grant_type=client_credentials", formBody, StringComparison.Ordinal);
                            Assert.Contains("client_id=test-client-id", formBody, StringComparison.Ordinal);
                            Assert.Contains("scope=api%3A%2F%2Ftarget%2F.default", formBody, StringComparison.Ordinal);

                            context.Response.StatusCode = (int)HttpStatusCode.OK;
                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsync(
                                "{\"token_type\":\"Bearer\",\"expires_in\":3600,\"access_token\":\"" + expectedAccessToken + "\"}");
                            return;
                        }

                        context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                    });
                });
            })
            .StartAsync(CancellationToken.None);

        var server = host.GetTestServer();

        var app = ConfidentialClientApplicationBuilder
            .Create("test-client-id")
            .WithOidcAuthority(authority)
            .WithClientSecret("test-client-secret")
            .WithHttpClientFactory(new TestMsalHttpClientFactory(server))
            .Build();

        var result = await app
            .AcquireTokenForClient(["api://target/.default"])
            .ExecuteAsync(CancellationToken.None);

        Assert.Equal(expectedAccessToken, result.AccessToken);
        Assert.True(metadataCalls > 0);
        Assert.True(tokenCalls > 0);
    }

    private sealed class TestMsalHttpClientFactory(TestServer server) : IMsalHttpClientFactory
    {
        public HttpClient GetHttpClient()
        {
            var client = server.CreateClient();
            client.BaseAddress = new Uri("https://mock.local/");
            return client;
        }
    }
}
