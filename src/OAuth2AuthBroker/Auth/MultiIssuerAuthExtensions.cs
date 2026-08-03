using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using OAuth2AuthBroker.Options;

namespace OAuth2AuthBroker.Auth;

public static class MultiIssuerAuthExtensions
{
    public static IServiceCollection AddMultiIssuerJwtAuthentication(this IServiceCollection services)
    {
        services.AddSingleton<IConfigureOptions<AuthenticationOptions>, ConfigureAuthenticationOptions>();
        services.AddSingleton<IConfigureOptions<JwtBearerOptions>, ConfigureJwtBearerOptions>();

        services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = AuthenticationSchemeNames.MultiIssuer;
                options.DefaultAuthenticateScheme = AuthenticationSchemeNames.MultiIssuer;
                options.DefaultChallengeScheme = AuthenticationSchemeNames.MultiIssuer;
            })
            .AddJwtBearer(AuthenticationSchemeNames.Fallback, options => {
                // This is a fallback scheme that will be used if no other scheme matches.
                options.TokenValidationParameters.ValidateAudience = false;
                options.TokenValidationParameters.ValidateIssuer = false;
            })
            .AddPolicyScheme(AuthenticationSchemeNames.MultiIssuer, "Multi issuer bearer", options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    if (!context.Request.Headers.TryGetValue("Authorization", out var authorizationHeader))
                    {
                        return AuthenticationSchemeNames.Fallback;
                    }

                    var token = ExtractBearerToken(authorizationHeader.ToString());
                    if (string.IsNullOrWhiteSpace(token))
                    {
                        return AuthenticationSchemeNames.Fallback;
                    }

                    var handler = new JsonWebTokenHandler();
                    if (!handler.CanReadToken(token))
                    {
                        return AuthenticationSchemeNames.Fallback;
                    }

                    var jwt = handler.ReadJsonWebToken(token);
                    var schemes = context.RequestServices.GetRequiredService<IssuerSchemeRegistry>();
                    return schemes.TryGetScheme(jwt.Issuer, out var scheme) ? scheme : AuthenticationSchemeNames.Fallback;
                };
            });

        return services;
    }

    private static string? ExtractBearerToken(string? authorizationHeader)
    {
        if (string.IsNullOrWhiteSpace(authorizationHeader))
        {
            return null;
        }

        const string bearerPrefix = "Bearer ";
        return authorizationHeader.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase)
            ? authorizationHeader[bearerPrefix.Length..].Trim()
            : null;
    }
}

public sealed class IssuerSchemeRegistry(IOptionsMonitor<BrokerConfigurationOptions> optionsMonitor)
{
    public bool TryGetScheme(string issuer, out string? scheme)
    {
        var allowedIssuer = optionsMonitor.CurrentValue.AllowedIssuers
            .FirstOrDefault(i => string.Equals(i.Issuer, issuer, StringComparison.OrdinalIgnoreCase));

        if (allowedIssuer is null)
        {
            scheme = null;
            return false;
        }

        scheme = AuthenticationSchemeNames.ForIssuer(allowedIssuer.Issuer);
        return true;
    }
}

internal sealed class ConfigureAuthenticationOptions(IOptionsMonitor<BrokerConfigurationOptions> optionsMonitor) : IConfigureOptions<AuthenticationOptions>
{
    public void Configure(AuthenticationOptions options)
    {
        foreach (var issuer in optionsMonitor.CurrentValue.AllowedIssuers)
        {
            options.AddScheme(AuthenticationSchemeNames.ForIssuer(issuer.Issuer), scheme =>
            {
                scheme.HandlerType = typeof(JwtBearerHandler);
                scheme.DisplayName = issuer.Issuer;
            });
        }
    }
}

internal sealed class ConfigureJwtBearerOptions(IOptionsMonitor<BrokerConfigurationOptions> optionsMonitor) : IConfigureNamedOptions<JwtBearerOptions>
{
    public void Configure(string? name, JwtBearerOptions options)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return;
        }

        var issuer = optionsMonitor.CurrentValue.AllowedIssuers.FirstOrDefault(x =>
            string.Equals(AuthenticationSchemeNames.ForIssuer(x.Issuer), name, StringComparison.Ordinal));

        if (issuer is null)
        {
            return;
        }

        options.MapInboundClaims = false;
        options.TokenValidationParameters.ValidateIssuer = true;
        options.TokenValidationParameters.ValidIssuer = issuer.Issuer;
        options.TokenValidationParameters.ValidateAudience = false;

        if (!string.IsNullOrWhiteSpace(issuer.MetadataAddress))
        {
            options.MetadataAddress = issuer.MetadataAddress;
        }
        else
        {
            options.Authority = issuer.Issuer;
        }

        options.RequireHttpsMetadata = true;
    }

    public void Configure(JwtBearerOptions options)
    {
    }
}
