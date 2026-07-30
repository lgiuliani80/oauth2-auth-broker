using OAuth2AuthBroker.Options;
using OAuth2AuthBroker.Services;

namespace OAuth2AuthBroker.Tests.Unit;

public sealed class RuleMatcherTests
{
    [Fact]
    public void Match_ShouldPreferExactAudienceAndClientId()
    {
        var options = new BrokerConfigurationOptions
        {
            AllowedIssuers =
            [
                new AllowedIssuerOptions
                {
                    Issuer = "https://issuer",
                    HandlingMode = TokenHandlingMode.Exchange
                }
            ],
            ReissueRules =
            [
                new ReissueRuleOptions
                {
                    Issuer = "https://issuer",
                    Audience = "*",
                    ClientIdSelector = "*",
                    Authority = "https://login.microsoftonline.com/tenant/v2.0",
                    ClientId = "client-wild"
                },
                new ReissueRuleOptions
                {
                    Issuer = "https://issuer",
                    Audience = "api://a",
                    ClientIdSelector = "my-app",
                    Authority = "https://login.microsoftonline.com/tenant/v2.0",
                    ClientId = "client-exact"
                }
            ]
        };

        var matcher = new RuleMatcher(new TestOptionsMonitor<BrokerConfigurationOptions>(options));
        var context = new InboundTokenContext("https://issuer", ["api://a"], "my-app", "raw");

        var result = matcher.Match(context);

        Assert.True(result.ShouldExchange);
        Assert.NotNull(result.Rule);
        Assert.Equal("client-exact", result.Rule!.ClientId);
    }

    [Fact]
    public void Match_ShouldRequestExchangeWithoutRuleWhenIssuerModeIsExchange()
    {
        var options = new BrokerConfigurationOptions
        {
            AllowedIssuers =
            [
                new AllowedIssuerOptions
                {
                    Issuer = "https://issuer",
                    HandlingMode = TokenHandlingMode.Exchange
                }
            ]
        };

        var matcher = new RuleMatcher(new TestOptionsMonitor<BrokerConfigurationOptions>(options));
        var context = new InboundTokenContext("https://issuer", ["api://a"], "my-app", "raw");

        var result = matcher.Match(context);

        Assert.True(result.ShouldExchange);
        Assert.Null(result.Rule);
    }

    [Fact]
    public void Match_ShouldPassThroughWhenIssuerModeIsPassThrough()
    {
        var options = new BrokerConfigurationOptions
        {
            AllowedIssuers =
            [
                new AllowedIssuerOptions
                {
                    Issuer = "https://issuer",
                    HandlingMode = TokenHandlingMode.PassThrough
                }
            ]
        };

        var matcher = new RuleMatcher(new TestOptionsMonitor<BrokerConfigurationOptions>(options));
        var context = new InboundTokenContext("https://issuer", ["api://a"], "my-app", "raw");

        var result = matcher.Match(context);

        Assert.False(result.ShouldExchange);
        Assert.Null(result.Rule);
    }
}
