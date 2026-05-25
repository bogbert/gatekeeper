# External IDP Enrichment Package

## Purpose

This package provides functionality to enrich authentication tokens from external Identity Providers (IDPs) with user data from Keycloak.

## Use Case

When using Gatekeeper with an external IDP (not our Keycloak IDP), the tokens issued by the external IDP may not contain all the claims and attributes needed for authorization. This package allows you to:

1. Accept tokens from an external IDP
2. Match the user from the external token with a Keycloak user
3. Enrich the token with roles, groups, and claims from Keycloak
4. Continue with authorization using Keycloak data

## Architecture

```
External IDP Token → Authentication → Enrichment → Authorization → Upstream
                         (valid)      (add claims)   (use claims)
```

## Components

### `config.go`
Configuration structure for external IDP enrichment settings.

### `models.go`
Data structures:
- `KeycloakUser`: represents a user exported from Keycloak
- `UsersData`: JSON file structure containing users
- `UserCache`: thread-safe in-memory cache of users

### `loader.go`
Functions to load and parse the users JSON file.

### `cache.go`
User cache management:
- Load users from JSON file
- Filter users based on tag
- Index users by username and email
- Auto-reload on file changes
- Thread-safe access with RWMutex

### `enricher.go`
Token enrichment logic:
- Extract matching value from external token
- Find corresponding Keycloak user
- Create enriched UserContext with Keycloak claims

## Configuration

Add to your Gatekeeper configuration:

```yaml
enable-external-idp-enrichment: true
extidp-users-file: /etc/gatekeeper/users.json
extidp-match-claim: preferred_username
extidp-users-file-match-field: username
extidp-user-filter: client-ABC
extidp-user-filter-is-regex: false
extidp-users-file-reload-interval: 30s
```

### Configuration Parameters

| Parameter                           | Required | Default              | Description                                            |
|-------------------------------------|----------|----------------------|--------------------------------------------------------|
| `enable-external-idp-enrichment`    | No       | `false`              | Enable/disable enrichment                              |
| `extidp-users-file`                 | Yes*     | -                    | Path to JSON file with Keycloak users                  |
| `extidp-match-claim`                | Yes*     | `preferred_username` | Claim in external token to match users                 |
| `extidp-users-file-match-field`     | Yes*     | `username`           | Field in JSON to match against (`username` or `email`) |
| `extidp-user-filter`                | No       | `""`                 | Filter users by tag (empty = accept all)               |
| `extidp-user-filter-is-regex`       | No       | `false`              | Treat filter as regex pattern                          |
| `extidp-users-file-reload-interval` | Yes*     | `30s`                | How often to check for file updates                    |

\* Required when `enable-external-idp-enrichment` is `true`

## Users JSON File Format

The JSON file must follow this structure:

```json
{
  "users": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "username": "john.doe",
      "email": "john.doe@example.com",
      "name": "John Doe",
      "tag": "client-ABC",
      "roles": ["user", "admin"],
      "groups": ["engineering"],
      "audiences": ["app1"],
      "acr": "1",
      "claims": {
        "department": "IT"
      }
    }
  ],
  "generated_at": "2026-02-11T17:00:00Z",
  "version": "1.0"
}
```

### Required Fields

- `id`: Keycloak user UUID
- `username`: User login name
- `email`: User email address
- `roles`: Array of user roles

### Optional Fields

- `preferred_username`: If absent, `email` will be used as fallback
- `name`: Display name (defaults to empty string)
- `tag`: User tag for filtering (defaults to empty string)
- `groups`: User groups (defaults to empty array)
- `audiences`: Authorized audiences (defaults to empty array)
- `acr`: Authentication level (defaults to empty string)
- `claims`: Custom attributes (defaults to empty object)

## File Update Strategy

To ensure atomic updates and avoid reading partial files:

1. Write to a timestamped temporary file
2. Update a symlink to point to the new file
3. Clean up old files

Example bash script:

```bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TEMP_FILE="users-${TIMESTAMP}.json"

# Write data
echo '{"users":[...]}' > "$TEMP_FILE"

# Atomic symlink update
ln -sf "$(basename "$TEMP_FILE")" users.json

# Cleanup (keep last 5)
ls -t users-*.json | tail -n +6 | xargs -r rm
```

## Thread Safety

The package is designed for concurrent access:

- File loading happens in a background goroutine
- The expensive operations (I/O, parsing, indexing) are done without locks
- Only the final cache swap (< 1ms) requires an exclusive lock
- Multiple request handlers can read the cache simultaneously
- Old cache remains valid during reload

Impact on request latency: < 1ms during cache reload (every 30 seconds by default).

## User Matching Logic

1. Extract match value from external token claim (e.g., `preferred_username`)
2. Look up user in cache by configured field (`username` or `email`)
3. If found, create enriched identity with Keycloak data
4. If not found, deny access

## Filtering Logic

Users are filtered based on the `tag` field:

### No Filter (Accept All)
```yaml
extidp-user-filter: ""
```
Accepts all users from the file.

### Literal Match
```yaml
extidp-user-filter: client-ABC
extidp-user-filter-is-regex: false
```
Accepts only users with `tag == "client-ABC"`.

### Regex Match
```yaml
extidp-user-filter: "^client-(ABC|XYZ)$"
extidp-user-filter-is-regex: true
```
Accepts users with `tag` matching the regex.

## Error Handling

- If JSON file is invalid: error logged, old cache retained, retry on next interval
- If user not found: access denied with detailed log
- If file read fails: error logged, old cache retained, retry on next interval

The system is designed to be resilient to transient errors.

## Integration Points

This package is integrated into Gatekeeper via:

1. **Initialization** (`pkg/keycloak/proxy/server.go`):
   - Create cache and enricher
   - Start background auto-reload goroutine

2. **Middleware** (`pkg/keycloak/proxy/middleware.go`):
   - `externalIDPEnrichmentMiddleware` intercepts authenticated requests
   - Enriches identity before authorization check

3. **Shutdown** (`pkg/keycloak/proxy/server.go`):
   - Stop auto-reload goroutine cleanly

## Example Scenarios

### Scenario 1: Single Client
All users belong to one client:

```yaml
extidp-user-filter: ""  # No filtering needed
```

### Scenario 2: Multiple Clients
Different clients identified by tag:

```yaml
# Instance for client-ABC
extidp-user-filter: client-ABC

# Instance for client-XYZ  
extidp-user-filter: client-XYZ
```

### Scenario 3: Client Family
Multiple related clients:

```yaml
extidp-user-filter: "^acme-.*$"
extidp-user-filter-is-regex: true
```

Matches `acme-prod`, `acme-staging`, etc.

## Security Notes

- Claims from external token are **completely replaced**, not merged
- Only users present in the JSON file can be authenticated
- Disabled users should be **removed** from the JSON file
- The JSON file should be readable only by the Gatekeeper process

## Maintenance

To minimize intrusion in the main Gatekeeper codebase:

- All enrichment logic is isolated in this package
- Integration points are clearly marked with comments
- Configuration follows Gatekeeper conventions
- No modification of core token validation logic
