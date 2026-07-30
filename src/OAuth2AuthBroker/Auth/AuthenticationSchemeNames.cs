namespace OAuth2AuthBroker.Auth;

public static class AuthenticationSchemeNames
{
    public const string MultiIssuer = "MultiIssuer";

    public static string ForIssuer(string issuer)
        => $"jwt::{issuer.GetHashCode(StringComparison.OrdinalIgnoreCase):X8}";
}
