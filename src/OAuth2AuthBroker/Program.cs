using OAuth2AuthBroker.Auth;
using OAuth2AuthBroker.Middleware;
using OAuth2AuthBroker.Options;
using OAuth2AuthBroker.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services
	.AddOptions<BrokerConfigurationOptions>()
	.Bind(builder.Configuration.GetSection(BrokerConfigurationOptions.SectionName))
	.ValidateDataAnnotations()
	.ValidateOnStart();
builder.Services.AddSingleton<Microsoft.Extensions.Options.IValidateOptions<BrokerConfigurationOptions>, BrokerOptionsValidator>();

var brokerOptions = builder.Configuration.GetSection(BrokerConfigurationOptions.SectionName).Get<BrokerConfigurationOptions>() ?? new BrokerConfigurationOptions();

if (string.IsNullOrWhiteSpace(brokerOptions.Cache.RedisConnectionString))
{
	builder.Services.AddDistributedMemoryCache();
}
else
{
	builder.Services.AddStackExchangeRedisCache(options =>
	{
		options.Configuration = brokerOptions.Cache.RedisConnectionString;
	});
}

builder.Services.AddSingleton<IssuerSchemeRegistry>();
builder.Services.AddMultiIssuerJwtAuthentication();

builder.Services.AddAuthorization(options =>
{
	options.AddPolicy("authenticated", policy => policy.RequireAuthenticatedUser());
});

builder.Services.AddSingleton<IRuleMatcher, RuleMatcher>();
builder.Services.AddSingleton<ITokenExchangeService, TokenExchangeService>();

builder.Services
	.AddReverseProxy()
	.LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<AuthenticatedRouteTokenMiddleware>();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));
app.MapReverseProxy();

app.Run();
