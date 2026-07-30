namespace OAuth2AuthBroker.Services;

public interface ITokenExchangeService
{
    Task<string> GetExchangedTokenAsync(InboundTokenContext tokenContext, CancellationToken cancellationToken);
}
