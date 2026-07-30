using OAuth2AuthBroker.Services;

namespace OAuth2AuthBroker.Tests.Unit;

public sealed class TokenCacheTtlCalculatorTests
{
    [Fact]
    public void Compute_ShouldReturnNull_WhenTokenAlmostExpired()
    {
        var now = new DateTimeOffset(2026, 7, 29, 10, 0, 0, TimeSpan.Zero);
        var ttl = TokenCacheTtlCalculator.Compute(
            accessToken: "not-a-jwt",
            configuredLocalTtl: TimeSpan.FromMinutes(10),
            timeProvider: new FakeTimeProvider(now),
            expiresIn: 3);

        Assert.Null(ttl);
    }

    [Fact]
    public void Compute_ShouldApplyMinLocalTtlRule()
    {
        var now = new DateTimeOffset(2026, 7, 29, 10, 0, 0, TimeSpan.Zero);
        var ttl = TokenCacheTtlCalculator.Compute(
            accessToken: "not-a-jwt",
            configuredLocalTtl: TimeSpan.FromMinutes(10),
            timeProvider: new FakeTimeProvider(now),
            expiresIn: 3600);

        Assert.NotNull(ttl);
        Assert.Equal(TimeSpan.FromMinutes(10), ttl!.Value.LocalTtl);
        Assert.Equal(TimeSpan.FromSeconds(3595), ttl.Value.DistributedTtl);
    }

    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
