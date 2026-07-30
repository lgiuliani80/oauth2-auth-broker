using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

namespace OAuth2AuthBroker.Services;

public static class InboundTokenContextFactory
{
    public static InboundTokenContext? FromClaimsPrincipal(ClaimsPrincipal principal, string rawAccessToken)
    {
        var issuer = principal.FindFirstValue(JwtRegisteredClaimNames.Iss);
        if (string.IsNullOrWhiteSpace(issuer))
        {
            return null;
        }

        var audiences = principal.FindAll("aud")
            .Select(c => c.Value)
            .Where(static v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var clientId = principal.FindFirstValue("azp") ?? principal.FindFirstValue("appid") ?? string.Empty;

        return new InboundTokenContext(issuer, audiences, clientId, rawAccessToken);
    }
}
