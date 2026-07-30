using Microsoft.Extensions.Options;
using OAuth2AuthBroker.Options;

namespace OAuth2AuthBroker.Services;

public sealed class RuleMatcher(IOptionsMonitor<BrokerConfigurationOptions> optionsMonitor) : IRuleMatcher
{
    private const string Wildcard = "*";

    public RuleMatchResult Match(InboundTokenContext tokenContext)
    {
        var options = optionsMonitor.CurrentValue;
        var issuerConfig = options.AllowedIssuers.FirstOrDefault(i =>
            string.Equals(i.Issuer, tokenContext.Issuer, StringComparison.OrdinalIgnoreCase));

        if (issuerConfig is null)
        {
            return RuleMatchResult.PassThrough;
        }

        if (issuerConfig.HandlingMode == TokenHandlingMode.PassThrough)
        {
            return RuleMatchResult.PassThrough;
        }

        var candidates = options.ReissueRules
            .Where(r => string.Equals(r.Issuer, tokenContext.Issuer, StringComparison.OrdinalIgnoreCase))
            .Select(rule => new
            {
                Rule = rule,
                AudienceScore = ComputeMatchScore(rule.Audience, tokenContext.Audiences),
                ClientScore = ComputeMatchScore(rule.ClientIdSelector, tokenContext.ClientId)
            })
            .Where(x => x.AudienceScore >= 0 && x.ClientScore >= 0)
            .OrderByDescending(x => x.AudienceScore)
            .ThenByDescending(x => x.ClientScore)
            .Select(x => x.Rule)
            .ToList();

        if (candidates.Count == 0)
        {
            return new RuleMatchResult(true, null);
        }

        return new RuleMatchResult(true, candidates[0]);
    }

    private static int ComputeMatchScore(string ruleAudience, IReadOnlyCollection<string> tokenAudiences)
    {
        if (string.Equals(ruleAudience, Wildcard, StringComparison.Ordinal))
        {
            return 0;
        }

        return tokenAudiences.Any(a => string.Equals(a, ruleAudience, StringComparison.OrdinalIgnoreCase)) ? 1 : -1;
    }

    private static int ComputeMatchScore(string ruleClient, string tokenClient)
    {
        if (string.Equals(ruleClient, Wildcard, StringComparison.Ordinal))
        {
            return 0;
        }

        return string.Equals(ruleClient, tokenClient, StringComparison.OrdinalIgnoreCase) ? 1 : -1;
    }
}
