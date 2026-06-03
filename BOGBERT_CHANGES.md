# Changes in the `bogbert` fork relative to `gogatekeeper-master`

This document lists all changes introduced in the `bogbert` branch that are not present in the `gogatekeeper-master` mainline branch.

---

## 1. External IDP Enrichment (major new feature)

**Files:** `pkg/keycloak/externalidp/` (new package), `pkg/keycloak/config/config.go`, `pkg/keycloak/proxy/server.go`, `pkg/keycloak/proxy/middleware.go`

Adds an "External IDP Enrichment" mode: when tokens come from an external IDP (e.g. Cognito), they can be enriched with the roles, groups, and claims of a matching Keycloak user, read from a JSON file.

### Package `pkg/keycloak/externalidp/`

- `config.go` — configuration structure for the enrichment mode
- `models.go` — data models (`KeycloakUser`, `UsersData`, `UserCache`)
- `loader.go` — loading and parsing of the JSON users file
- `cache.go` — thread-safe cache with automatic reload on file change, filtering by tag (literal or regex)
- `enricher.go` — enrichment logic: extraction of the match claim from the external token, lookup of the Keycloak user, creation of an enriched `UserContext`
- `README.md` — package documentation

### New configuration parameters

| Parameter                           | Default              | Description                                                     |
|-------------------------------------|----------------------|-----------------------------------------------------------------|
| `enable-external-idp-enrichment`    | `false`              | Enable/disable enrichment                                       |
| `extidp-users-file`                 | —                    | Path to the JSON file containing Keycloak users                 |
| `extidp-match-claim`                | `preferred_username` | Claim in the external token used for matching                   |
| `extidp-users-file-match-field`     | `username`           | Field in the JSON file to match against (`username` or `email`) |
| `extidp-user-filter`                | `""`                 | Filter on a user tag (empty = accept all)                       |
| `extidp-user-filter-is-regex`       | `false`              | Treat the filter as a regular expression                        |
| `extidp-users-file-reload-interval` | `30s`                | Interval for checking file updates                              |

### Proxy integration

- `server.go`: initializes the `Enricher` and `UserCache` at startup, launches automatic background reload
- `middleware.go`: new `externalIDPEnrichmentMiddleware` injected into the middleware chain after authentication, replacing `scope.Identity` with the enriched identity

---

## 2. Unconditional refresh token compression

**Files:** `pkg/keycloak/proxy/handlers.go`, `pkg/proxy/middleware/oauth.go`, `pkg/keycloak/proxy/server.go`

Refresh tokens are now **always** encrypted and compressed, regardless of the `enable-compress-token` setting.

- The compression buffer pool (`LimitedBufferPool`) is always created at startup (no longer conditional on `EnableCompressToken`)
- `oauthCallbackHandler`, `loginHandler`, and `AuthenticationMiddleware` exclusively use `session.EncryptAndCompressToken` for refresh tokens
- Tests updated accordingly (`pkg/testsuite/middleware_test.go`)

---

## 3. Cognito support: roles passed as a string

**Files:** `pkg/proxy/models/user.go`, `pkg/proxy/session/token.go`

Cognito cannot return client roles as a JSON array; it sends them as a bracket-delimited string (e.g. `"[role1, role2]"`).

- `models.go`: added `CognitoRoles string` field (mapped to the `role` claim) in `CustClaims`
- `token.go`: if `roleList` is empty after standard extraction, falls back to parsing `CognitoRoles` as `[role1, role2, ...]`

---

## 4. Support for Cognito Discovery URIs

**File:** `pkg/keycloak/config/config.go`

The `discovery-uri` validation now accepts Cognito URIs (of the form `/<userPoolId>/`) in addition to standard Keycloak URIs.

- The more specific Keycloak pattern is tested first
- Falls back to a Cognito pattern (`/(?P<userPoolId>[^/]+)/?$`)
- `Realm` is extracted from the Cognito `userPoolId`

---

## 5. `{hostname}` substitution in redirection URLs

**Files:** `pkg/utils/utils.go`, `pkg/proxy/handlers/handlers.go`, `pkg/keycloak/proxy/handlers.go`

Added `utils.ReplaceHostnamePlaceholder(s, req)`, which replaces the `{hostname}` placeholder with the actual hostname from the HTTP request (preferring the `X-Forwarded-Host` header).

Used in:
- `GetRedirectionURL` — for `redirection-url`
- `logoutHandler` — for `post-logout-redirect-uri` and `redirection-url`

This allows a single configuration to be deployed across multiple domains.

---

## 6. `redirect_uri` query parameter on `/oauth/authorize`

**File:** `pkg/keycloak/proxy/handlers.go`

The `/oauth/authorize` endpoint now accepts a `redirect_uri` query parameter. If provided and if it is a relative path (to prevent open-redirect attacks), the value is stored in the `request_uri` cookie (base64-encoded), causing `oauthCallbackHandler` to redirect there after a successful login instead of defaulting to `/`.

---

## 7. Automatic IDP reconnection at startup

**File:** `pkg/keycloak/config/config.go`

Two new parameters:

| Parameter                | Default | Description                                                               |
|--------------------------|---------|---------------------------------------------------------------------------|
| `enable-idp-reconnect`   | `false` | Retry IDP connection indefinitely at startup instead of exiting           |
| `idp-reconnect-interval` | `60s`   | Interval between reconnection attempts once initial retries are exhausted |

---

## 8. Upstream headers: unconditional claim writing, reduced default headers

**File:** `pkg/proxy/middleware/base.go`

Two changes in `IdentityHeadersMiddleware`:

1. **Claims always written**: if a header mapped from claims has no value, it is now written with an empty value (`""`). This prevents a malicious client from injecting spoofed headers that the proxy would otherwise not have overwritten.

2. **Reduced default headers**: several headers deemed unnecessary for this fork's use cases have been commented out to avoid exceeding HTTP header size limits:
   - `X-Auth-Audience`
   - `X-Auth-Expiresin`
   - `X-Auth-Groups`
   - `X-Auth-Subject`
   - `X-Auth-Userid`

   The headers `X-Auth-Email`, `X-Auth-Roles`, and `X-Auth-Username` are kept.

---

## 9. Improved logging

**Files:** `pkg/proxy/middleware/oauth.go`, `pkg/proxy/middleware/security.go`, `pkg/keycloak/proxy/handlers.go`

- `AuthenticationMiddleware`: identity (username, ID) is extracted before token verification to enrich logs even on failure; token expiration date is added to logs for expired tokens
- `AdmissionMiddleware`: `user.Name` added to access-denied log entries
- `logoutHandler`: `user.Name` added to successful logout log entries

---

## 10. Dockerfile: configurable base image

**File:** `Dockerfile`

The base image is now configurable via a build argument `BASE_IMG` (default: `scratch`), allowing the image to be built from a different base when needed (e.g. for debugging or additional tooling).

```dockerfile
ARG BASE_IMG=scratch
FROM ${BASE_IMG}
```

---

## Summary of modified files

| File                                | Nature of change                                                                        |
|-------------------------------------|-----------------------------------------------------------------------------------------|
| `Dockerfile`                        | Configurable base image                                                                 |
| `pkg/apperrors/apperrors.go`        | New error values (external IDP cache)                                                   |
| `pkg/keycloak/config/config.go`     | New parameters (external IDP, IDP reconnect, Cognito discovery URI)                     |
| `pkg/keycloak/externalidp/`         | **New package** — external IDP enrichment                                               |
| `pkg/keycloak/proxy/handlers.go`    | Refresh token compression, `redirect_uri` on `/oauth/authorize`, `{hostname}` in logout |
| `pkg/keycloak/proxy/middleware.go`  | New external IDP enrichment middleware                                                  |
| `pkg/keycloak/proxy/oauth_proxy.go` | `ExternalIDPEnricher` and `ExternalIDPStopCh` fields added to the struct                |
| `pkg/keycloak/proxy/server.go`      | External IDP init, compression pool always created                                      |
| `pkg/proxy/handlers/handlers.go`    | `{hostname}` in `GetRedirectionURL`                                                     |
| `pkg/proxy/middleware/base.go`      | Claims written as empty strings, reduced default headers                                |
| `pkg/proxy/middleware/oauth.go`     | Enriched logs, unconditional refresh token compression                                  |
| `pkg/proxy/middleware/security.go`  | `user.Name` added to access-denied logs                                                 |
| `pkg/proxy/models/user.go`          | `CognitoRoles` field in `CustClaims`                                                    |
| `pkg/proxy/session/token.go`        | Cognito string-format role parsing                                                      |
| `pkg/testsuite/middleware_test.go`  | Tests updated for unconditional compression                                             |
| `pkg/utils/utils.go`                | `ReplaceHostnamePlaceholder` function                                                   |
