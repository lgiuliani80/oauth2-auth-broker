namespace OAuth2AuthBroker.Services;

public sealed record InboundTokenContext(
    string Issuer,
    IReadOnlyCollection<string> Audiences,
    string ClientId,
    string RawAccessToken);
