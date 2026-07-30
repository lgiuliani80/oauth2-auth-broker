using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using OAuth2AuthBroker.Options;

namespace OAuth2AuthBroker.Services;

public sealed class TokenExchangeService : ITokenExchangeService
{
    private readonly IDistributedCache _distributedCache;
    private readonly IRuleMatcher _ruleMatcher;
    private readonly ILogger<TokenExchangeService> _logger;

    public TokenExchangeService(
        IDistributedCache distributedCache,
        IRuleMatcher ruleMatcher,
        ILogger<TokenExchangeService> logger)
    {
        _distributedCache = distributedCache;
        _ruleMatcher = ruleMatcher;
        _logger = logger;
    }

    public async Task<string> GetExchangedTokenAsync(InboundTokenContext tokenContext, CancellationToken cancellationToken)
    {
        var match = _ruleMatcher.Match(tokenContext);
        if (!match.ShouldExchange)
        {
            return tokenContext.RawAccessToken;
        }

        if (match.Rule is null)
        {
            throw new InvalidOperationException("Issuer requires token exchange but no matching reissue rule was found.");
        }

        var scope = string.IsNullOrWhiteSpace(match.Rule.Scope)
            ? ResolveDefaultScope(tokenContext.Audiences)
            : match.Rule.Scope!;

        var response = await RequestTokenWithMsalAsync(
            match.Rule,
            scope,
            tokenContext.RawAccessToken,
            _distributedCache,
            cancellationToken);

        _logger.LogDebug("Token acquired via MSAL cache for {Authority} / {ClientId}", match.Rule.Authority, match.Rule.ClientId);
        return response.AccessToken;
    }

    private static async Task<TokenResponse> RequestTokenWithMsalAsync(
        ReissueRuleOptions rule,
        string scope,
        string inboundAccessToken,
        IDistributedCache distributedCache,
        CancellationToken cancellationToken)
    {
        var builder = ConfidentialClientApplicationBuilder
            .Create(rule.ClientId)
            .WithOidcAuthority(rule.Authority);

        if (!string.IsNullOrWhiteSpace(rule.ClientSecret))
        {
            builder = builder.WithClientSecret(rule.ClientSecret);
        }
        else if (!string.IsNullOrWhiteSpace(rule.ClientCertificate))
        {
            var certificate = LoadCertificate(rule.ClientCertificate, rule.ClientCertificatePassword);
            builder = builder.WithCertificate(certificate);
        }
        else
        {
            if (string.IsNullOrWhiteSpace(inboundAccessToken))
            {
                throw new InvalidOperationException("Client assertion flow requires the incoming JWT token.");
            }

            builder = builder.WithClientAssertion((AssertionRequestOptions _) => Task.FromResult(inboundAccessToken));
        }

        var app = builder.Build();
        ConfigureMsalTokenCache(
            app.AppTokenCache,
            distributedCache,
            BuildAppTokenCacheKeyPrefix(rule.Authority, rule.ClientId));

        var result = await app.AcquireTokenForClient([scope]).ExecuteAsync(cancellationToken);

        return new TokenResponse
        {
            AccessToken = result.AccessToken,
            ExpiresIn = (long)(result.ExpiresOn - DateTimeOffset.UtcNow).TotalSeconds,
            Scope = string.Join(' ', result.Scopes)
        };
    }

    private static string ResolveDefaultScope(IReadOnlyCollection<string> audiences)
    {
        var firstAudience = audiences.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(firstAudience))
        {
            throw new InvalidOperationException("Cannot resolve default scope because inbound token has no audience claim.");
        }

        return $"{firstAudience}/.default";
    }

    private static string BuildAppTokenCacheKeyPrefix(string authority, string clientId)
        => $"msal:app-token:{authority}|{clientId}";

    private static void ConfigureMsalTokenCache(
        ITokenCache tokenCache,
        IDistributedCache distributedCache,
        string cacheKeyPrefix)
    {
        tokenCache.SetBeforeAccessAsync(async args =>
        {
            var cacheKey = BuildMsalCacheKey(cacheKeyPrefix, args);
            var bytes = await distributedCache.GetAsync(cacheKey, args.CancellationToken).ConfigureAwait(false);
            if (bytes is { Length: > 0 })
            {
                args.TokenCache.DeserializeMsalV3(bytes, shouldClearExistingCache: true);
            }
        });

        tokenCache.SetAfterAccessAsync(async args =>
        {
            if (!args.HasStateChanged)
            {
                return;
            }

            var cacheKey = BuildMsalCacheKey(cacheKeyPrefix, args);
            var bytes = args.TokenCache.SerializeMsalV3();

            await distributedCache.SetAsync(
                cacheKey,
                bytes,
                new DistributedCacheEntryOptions(),
                args.CancellationToken).ConfigureAwait(false);
        });
    }

    private static string BuildMsalCacheKey(string cacheKeyPrefix, TokenCacheNotificationArgs args)
    {
        if (string.IsNullOrWhiteSpace(args.ClientId))
        {
            return cacheKeyPrefix;
        }

        return $"{cacheKeyPrefix}|{args.ClientId}";
    }

    private static X509Certificate2 LoadCertificate(string certificateHint, string? password)
    {
        if (File.Exists(certificateHint))
        {
            return X509CertificateLoader.LoadPkcs12FromFile(certificateHint, password, X509KeyStorageFlags.EphemeralKeySet);
        }

        var thumbprint = certificateHint.Replace(" ", string.Empty, StringComparison.Ordinal);
        var cert = FindByThumbprint(StoreLocation.CurrentUser, thumbprint)
            ?? FindByThumbprint(StoreLocation.LocalMachine, thumbprint);

        return cert ?? throw new InvalidOperationException($"Certificate '{certificateHint}' was not found in CurrentUser or LocalMachine stores.");
    }

    private static X509Certificate2? FindByThumbprint(StoreLocation storeLocation, string thumbprint)
    {
        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadOnly);

        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        return matches.Count > 0 ? matches[0] : null;
    }
}
