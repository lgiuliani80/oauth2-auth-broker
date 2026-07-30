using Microsoft.AspNetCore.Authorization;
using OAuth2AuthBroker.Services;

namespace OAuth2AuthBroker.Middleware;

public sealed class AuthenticatedRouteTokenMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, IRuleMatcher ruleMatcher, ITokenExchangeService tokenExchangeService)
    {
        var endpoint = context.GetEndpoint();
        var authorizeData = endpoint?.Metadata.GetOrderedMetadata<IAuthorizeData>() ?? [];

        var requiresAuthenticatedPolicy = authorizeData.Any(static a =>
            string.Equals(a.Policy, "authenticated", StringComparison.OrdinalIgnoreCase));

        if (!requiresAuthenticatedPolicy)
        {
            await next(context);
            return;
        }

        if (context.User?.Identity?.IsAuthenticated != true)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        if (!context.Request.Headers.TryGetValue("Authorization", out var authorizationHeader))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var bearerToken = ExtractBearerToken(authorizationHeader.ToString());
        if (string.IsNullOrWhiteSpace(bearerToken))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var tokenContext = InboundTokenContextFactory.FromClaimsPrincipal(context.User, bearerToken);
        if (tokenContext is null)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var match = ruleMatcher.Match(tokenContext);
        if (match.ShouldExchange && match.Rule is null)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("No matching exchange rule was found for the authenticated route.");
            return;
        }

        var tokenForBackend = match.ShouldExchange
            ? await tokenExchangeService.GetExchangedTokenAsync(tokenContext, context.RequestAborted)
            : tokenContext.RawAccessToken;

        context.Request.Headers.Authorization = $"Bearer {tokenForBackend}";

        await next(context);
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
