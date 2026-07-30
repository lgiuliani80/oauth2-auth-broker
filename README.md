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
- Uses only MSAL for token acquisition.
- Reissue rules specify `Authority`, not `TokenEndpoint`.
- Target IdPs used for token reissue must support OIDC discovery because MSAL is configured through `WithOidcAuthority(...)`.

## Cache behavior

- Cache key: `authority|client_id|scope`.
- Local TTL: `min(LocalTtlMinutes, exp-now-5s)`.
- Distributed TTL: `exp-now-5s`.
- Distributed cache provider:
  - default: `MemoryDistributedCache`
  - if `AuthBroker:Cache:RedisConnectionString` is set: `StackExchange.RedisCache`

## OIDC authority notes

- Entra ID example authority: `https://login.microsoftonline.com/<tenant-id>/v2.0`
- ADFS example authority: base ADFS URL, for example `https://adfs.contoso.local/adfs`
- This implementation intentionally relies on OIDC discovery through MSAL instead of deriving the token endpoint manually.

## Run

```powershell
dotnet run --project src/OAuth2AuthBroker/OAuth2AuthBroker.csproj
```

## Test

```powershell
dotnet test tests/OAuth2AuthBroker.Tests/OAuth2AuthBroker.Tests.csproj
```
