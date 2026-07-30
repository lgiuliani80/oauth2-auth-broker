namespace OAuth2AuthBroker.Services;

public interface IRuleMatcher
{
    RuleMatchResult Match(InboundTokenContext tokenContext);
}
