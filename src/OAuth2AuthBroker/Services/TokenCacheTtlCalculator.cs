using Microsoft.IdentityModel.JsonWebTokens;
using OAuth2AuthBroker.Options;

namespace OAuth2AuthBroker.Services;

public static class TokenCacheTtlCalculator
{
    private static readonly TimeSpan SafetyWindow = TimeSpan.FromSeconds(5);

    public static (TimeSpan LocalTtl, TimeSpan DistributedTtl)? Compute(
        string accessToken,
        TimeSpan configuredLocalTtl,
        TimeProvider timeProvider,
        long? expiresIn)
    {
        var now = timeProvider.GetUtcNow();
        DateTimeOffset? expiresAt = TryReadJwtExpiration(accessToken);

        if (expiresAt is null && expiresIn is not null)
        {
            expiresAt = now.AddSeconds(expiresIn.Value);
        }

        if (expiresAt is null)
        {
            return (configuredLocalTtl, configuredLocalTtl);
        }

        var remaining = expiresAt.Value - now - SafetyWindow;
        if (remaining <= TimeSpan.Zero)
        {
            return null;
        }

        var localTtl = remaining < configuredLocalTtl ? remaining : configuredLocalTtl;
        return (localTtl, remaining);
    }

    private static DateTimeOffset? TryReadJwtExpiration(string token)
    {
        var handler = new JsonWebTokenHandler();
        if (!handler.CanReadToken(token))
        {
            return null;
        }

        var jwt = handler.ReadJsonWebToken(token);
        if (jwt.ValidTo == DateTime.MinValue)
        {
            return null;
        }

        return new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero);
    }
}
