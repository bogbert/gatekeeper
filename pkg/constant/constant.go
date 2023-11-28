package constant

import "time"

type contextKey int8

const (
	Prog        = "gatekeeper"
	Author      = "go-gatekeeper"
	Email       = ""
	Description = "is a proxy using the keycloak service for auth and authorization"

	AuthorizationHeader = "Authorization"
	AuthorizationType   = "Bearer"
	EnvPrefix           = "PROXY_"
	HeaderUpgrade       = "Upgrade"
	VersionHeader       = "X-Auth-Proxy-Version"
	UMATicketHeader     = "WWW-Authenticate"

	AuthorizationURL = "/authorize"
	CallbackURL      = "/callback"
	ExpiredURL       = "/expired"
	HealthURL        = "/health"
	LoginURL         = "/login"
	LogoutURL        = "/logout"
	MetricsURL       = "/metrics"
	TokenURL         = "/token"
	DebugURL         = "/debug/pprof"
	DiscoveryURL     = "/discovery"

	ClaimResourceRoles = "roles"

	AccessCookie       = "kc-access"
	RefreshCookie      = "kc-state"
	RequestURICookie   = "request_uri"
	RequestStateCookie = "OAuth_Token_Request_State"
	PKCECookie         = "pkce"
	IDTokenCookie      = "id_token"
	UMACookie          = "uma_token"
	// case is like this because go net package canonicalizes it
	// to this form, see net package
	UMAHeader      = "X-Uma-Token"
	UnsecureScheme = "http"
	SecureScheme   = "https"
	AnyMethod      = "ANY"

	_ contextKey = iota
	ContextScopeName
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"
	HeaderXHMAC         = "X-HMAC-SHA256"

	DurationType = "time.Duration"

	// SameSite cookie config options
	SameSiteStrict = "Strict"
	SameSiteLax    = "Lax"
	SameSiteNone   = "None"

	AllPath = "/*"

	IdpWellKnownURI   = "/.well-known/openid-configuration"
	IdpCertsURI       = "/protocol/openid-connect/certs"
	IdpTokenURI       = "/protocol/openid-connect/token"
	IdpAuthURI        = "/protocol/openid-connect/auth"
	IdpUserURI        = "/protocol/openid-connect/userinfo"
	IdpLogoutURI      = "/protocol/openid-connect/logout"
	IdpRevokeURI      = "/protocol/openid-connect/revoke"
	IdpResourceSetURI = "/authz/protection/resource_set"
	IdpProtectPermURI = "/authz/protection/permission"

	InvalidCookieDuration = -10 * time.Hour
)
