using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using OAuth2AuthBroker.Options;

namespace OAuth2AuthBroker.Services;

public sealed class TokenExchangeService : ITokenExchangeService
{
    private readonly HybridCache _hybridCache;
    private readonly IRuleMatcher _ruleMatcher;
    private readonly IOptionsMonitor<BrokerConfigurationOptions> _optionsMonitor;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<TokenExchangeService> _logger;

    public TokenExchangeService(
        HybridCache hybridCache,
        IRuleMatcher ruleMatcher,
        IOptionsMonitor<BrokerConfigurationOptions> optionsMonitor,
        TimeProvider timeProvider,
        ILogger<TokenExchangeService> logger)
    {
        _hybridCache = hybridCache;
        _ruleMatcher = ruleMatcher;
        _optionsMonitor = optionsMonitor;
        _timeProvider = timeProvider;
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

        var cacheKey = BuildCacheKey(match.Rule.Authority, match.Rule.ClientId, scope);

        var cached = await TryGetCachedTokenAsync(cacheKey, cancellationToken);
        if (!string.IsNullOrWhiteSpace(cached))
        {
            _logger.LogDebug("Token cache hit for {Authority} / {ClientId}", match.Rule.Authority, match.Rule.ClientId);
            return cached;
        }

        _logger.LogDebug("Token cache miss for {Authority} / {ClientId}", match.Rule.Authority, match.Rule.ClientId);

        var response = await RequestTokenWithMsalAsync(match.Rule, scope, tokenContext.RawAccessToken, cancellationToken);
        var localTtlConfigured = TimeSpan.FromMinutes(Math.Max(_optionsMonitor.CurrentValue.Cache.LocalTtlMinutes, 1));
        var ttl = TokenCacheTtlCalculator.Compute(response.AccessToken, localTtlConfigured, _timeProvider, response.ExpiresIn);

        if (ttl is { } configuredTtls)
        {
            await _hybridCache.SetAsync(
                cacheKey,
                response.AccessToken,
                options: new HybridCacheEntryOptions
                {
                    LocalCacheExpiration = configuredTtls.LocalTtl,
                    Expiration = configuredTtls.DistributedTtl
                },
                cancellationToken: cancellationToken);
        }

        return response.AccessToken;
    }

    private async Task<string?> TryGetCachedTokenAsync(string cacheKey, CancellationToken cancellationToken)
    {
        return await _hybridCache.GetOrCreateAsync(
            cacheKey,
            static _ => new ValueTask<string?>(result: null),
            options: new HybridCacheEntryOptions
            {
                Flags = HybridCacheEntryFlags.DisableUnderlyingData
            },
            cancellationToken: cancellationToken);
    }

    private static async Task<TokenResponse> RequestTokenWithMsalAsync(
        ReissueRuleOptions rule,
        string scope,
        string inboundAccessToken,
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

    private static string BuildCacheKey(string authority, string clientId, string scope)
        => $"{authority}|{clientId}|{scope}";

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
