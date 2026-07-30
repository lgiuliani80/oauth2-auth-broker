using OAuth2AuthBroker.Options;

namespace OAuth2AuthBroker.Services;

public sealed record RuleMatchResult(bool ShouldExchange, ReissueRuleOptions? Rule)
{
    public static RuleMatchResult PassThrough { get; } = new(false, null);
}
