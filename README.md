# OAuth2 Auth Broker (YARP, .NET 10)

Reverse proxy OAuth2 broker based on YARP that:

- Accepts JWTs from multiple OIDC issuers.
- Applies token pass-through or token exchange only on routes protected by policy `authenticated`.
- Leaves routes without authorization policy in pure pass-through mode.
- Caches exchanged tokens with HybridCache.

## Current implementation highlights

- Multi-issuer authentication with per-issuer metadata override support.
- Rule matching on `(issuer, audience, client_id)` where `audience` and `client_id` support wildcard `*`.
- `client_id` is extracted from incoming claims `azp` then `appid`.
- Token exchange supports:
  - `client_secret`
  - `client_certificate` (file path or thumbprint from CurrentUser/LocalMachine)
  - federated credentials fallback (incoming JWT forwarded as `client_assertion`)
- Uses MSAL for Entra-compatible token endpoints when possible.

## Cache behavior

- Cache key: `token_endpoint|client_id|scope`.
- Local TTL: `min(LocalTtlMinutes, exp-now-5s)`.
- Distributed TTL: `exp-now-5s`.
- Distributed cache provider:
  - default: `MemoryDistributedCache`
  - if `AuthBroker:Cache:RedisConnectionString` is set: `StackExchange.RedisCache`

## Run

```powershell
dotnet run --project src/OAuth2AuthBroker/OAuth2AuthBroker.csproj
```

## Test

```powershell
dotnet test tests/OAuth2AuthBroker.Tests/OAuth2AuthBroker.Tests.csproj
```
