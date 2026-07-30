using Microsoft.Extensions.Options;

namespace OAuth2AuthBroker.Options;

public sealed class BrokerOptionsValidator : IValidateOptions<BrokerConfigurationOptions>
{
    public ValidateOptionsResult Validate(string? name, BrokerConfigurationOptions options)
    {
        var errors = new List<string>();

        if (options.AllowedIssuers.Count == 0)
        {
            errors.Add("At least one allowed issuer must be configured.");
        }

        var duplicateIssuers = options.AllowedIssuers
            .GroupBy(i => i.Issuer, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToArray();

        if (duplicateIssuers.Length > 0)
        {
            errors.Add($"Duplicate allowed issuers: {string.Join(", ", duplicateIssuers)}");
        }

        for (var i = 0; i < options.ReissueRules.Count; i++)
        {
            var rule = options.ReissueRules[i];
            var hasSecret = !string.IsNullOrWhiteSpace(rule.ClientSecret);
            var hasCertificate = !string.IsNullOrWhiteSpace(rule.ClientCertificate);

            if (hasSecret && hasCertificate)
            {
                errors.Add($"ReissueRules[{i}] cannot specify both client_secret and client_certificate.");
            }

            if (!hasCertificate && !string.IsNullOrWhiteSpace(rule.ClientCertificatePassword))
            {
                errors.Add($"ReissueRules[{i}] has client_certificate_password but no client_certificate.");
            }
        }

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }
}
