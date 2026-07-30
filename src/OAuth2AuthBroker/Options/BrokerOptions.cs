using System.ComponentModel.DataAnnotations;

namespace OAuth2AuthBroker.Options;

public sealed class BrokerConfigurationOptions
{
    public const string SectionName = "AuthBroker";

    [Required]
    public List<AllowedIssuerOptions> AllowedIssuers { get; init; } = [];

    public List<ReissueRuleOptions> ReissueRules { get; init; } = [];

    [Required]
    public CacheOptions Cache { get; init; } = new();
}

public sealed class AllowedIssuerOptions
{
    [Required]
    public string Issuer { get; init; } = string.Empty;

    public string? MetadataAddress { get; init; }

    public TokenHandlingMode HandlingMode { get; init; } = TokenHandlingMode.PassThrough;
}

public enum TokenHandlingMode
{
    PassThrough = 0,
    Exchange = 1
}

public sealed class ReissueRuleOptions
{
    [Required]
    public string Issuer { get; init; } = string.Empty;

    [Required]
    public string Audience { get; init; } = "*";

    [Required]
    public string ClientIdSelector { get; init; } = "*";

    [Required]
    [Url]
    public string TokenEndpoint { get; init; } = string.Empty;

    [Required]
    public string ClientId { get; init; } = string.Empty;

    public string? ClientSecret { get; init; }

    public string? ClientCertificate { get; init; }

    public string? ClientCertificatePassword { get; init; }

    public string? Scope { get; init; }
}

public sealed class CacheOptions
{
    public int LocalTtlMinutes { get; init; } = 10;

    public string? RedisConnectionString { get; init; }
}
