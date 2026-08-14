package middleware

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/purell"
	"github.com/go-chi/chi/v5/middleware"
	uuid "github.com/gofrs/uuid"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/core"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/metrics"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

const (
	normalizeFlags purell.NormalizationFlags = purell.FlagRemoveDotSegments | purell.FlagRemoveDuplicateSlashes
)

// isUnreservedRFC3986 reports whether b is an RFC 3986 §2.3 unreserved
// character. Percent-encoded octets of these bytes carry no special
// meaning and can be safely decoded before resource rules are matched.
func isUnreservedRFC3986(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '.' || b == '_' || b == '~'
}

func hexDigitValue(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func upperHexDigit(b byte) byte {
	if b >= 'a' && b <= 'f' {
		return b - 'a' + 'A'
	}

	return b
}

// normalizePathEncoding mirrors the RFC 3986 §6.2.2.2 percent-encoding
// normalization rule that nginx and most reverse proxies also apply
// before evaluating their routing rules: percent-encoded octets that
// correspond to unreserved characters are decoded (e.g. "%6a" -> "j"),
// while every other percent-encoding - reserved characters such as
// "%2F" or "%3F", and malformed/incomplete escapes - is left untouched
// (aside from canonicalizing the hex digits to uppercase).
//
// This keeps resource rules such as "uri=/joblauncher*" from being
// bypassed by trivially percent-encoding otherwise-plain path
// characters, without collapsing an encoded "%2F" into a literal path
// separator, which could change which resource rule a request logically
// belongs to.
func normalizePathEncoding(raw string) string {
	var buf strings.Builder
	buf.Grow(len(raw))

	for i := 0; i < len(raw); i++ {
		c := raw[i]

		if c == '%' && i+2 < len(raw) {
			hi, hiOk := hexDigitValue(raw[i+1])
			lo, loOk := hexDigitValue(raw[i+2])

			if hiOk && loOk {
				decoded := hi<<4 | lo

				if isUnreservedRFC3986(decoded) {
					buf.WriteByte(decoded)
				} else {
					buf.WriteByte('%')
					buf.WriteByte(upperHexDigit(raw[i+1]))
					buf.WriteByte(upperHexDigit(raw[i+2]))
				}

				i += 2

				continue
			}
		}

		buf.WriteByte(c)
	}

	return buf.String()
}

// normalizeStructural applies the same dot-segment/duplicate-slash
// canonicalization purell performs, plus the leading-slash fixup, to a bare
// path string without touching its percent-encoding. Used to derive both the
// fully-decoded and the RFC-3986-selective candidate paths from a common
// code path.
func normalizeStructural(path string) string {
	u := &url.URL{Path: path}
	purell.NormalizeURL(u, normalizeFlags)

	if !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}

	return u.Path
}

// isOAuthControlPlanePath reports whether a fully-decoded, normalized path
// falls under Gatekeeper's own internal control-plane prefix (e.g. /oauth).
// That prefix has a single, fixed security posture (unlike user-defined
// uri: resource rules), so there is no rule-confusion risk in recognizing it
// via full decoding - and doing so keeps it robust against obfuscation
// attempts, matching the pre-existing behavior this endpoint has always
// relied on.
func isOAuthControlPlanePath(fullyDecodedPath, oauthPrefix string) bool {
	if oauthPrefix == "" {
		return false
	}

	return fullyDecodedPath == oauthPrefix || strings.HasPrefix(fullyDecodedPath, oauthPrefix+"/")
}

// EntrypointMiddleware is custom filtering for incoming requests.
func EntrypointMiddleware(logger *zap.Logger, oauthPrefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			// @step: create a context for the request
			scope := &models.RequestScope{}
			// Save the exact formatting of the incoming request so we can use it later
			scope.Path = req.URL.Path
			scope.RawPath = req.URL.RawPath
			scope.Logger = logger

			// Compute two candidate paths for routing:
			//
			//  - fullyDecodedPath: legacy, fully-decoded-then-normalized
			//    behavior. Used only to robustly recognize Gatekeeper's own
			//    internal /oauth control-plane endpoints, which need to
			//    resist obfuscation and have no per-request rule ambiguity.
			//  - strictPath: percent-encoded reserved characters (e.g. %2F,
			//    %3F) are left opaque, only RFC 3986 unreserved characters
			//    are decoded. This is the representation used to match
			//    user-configured uri: resource rules, so an encoded
			//    reserved character can't make a request match a different
			//    (weaker) resource rule than the literal string warrants.
			//
			// This mirrors nginx: location matching decodes/normalizes,
			// but the original wire-format path (preserved in scope.Path /
			// scope.RawPath and restored below) is what actually reaches
			// the upstream.
			fullyDecodedPath := normalizeStructural(req.URL.Path)
			strictPath := normalizeStructural(normalizePathEncoding(req.URL.EscapedPath()))

			matchPath := strictPath
			if isOAuthControlPlanePath(fullyDecodedPath, oauthPrefix) {
				matchPath = fullyDecodedPath
			}

			req.URL.Path = matchPath
			req.URL.RawPath = matchPath

			resp := middleware.NewWrapResponseWriter(wrt, 1)
			start := time.Now()
			// All the processing, including forwarding the request upstream and getting the response,
			// happens here in this chain.
			next.ServeHTTP(resp, req.WithContext(context.WithValue(req.Context(), constant.ContextScopeName, scope)))

			// @metric record the time taken then response code
			metrics.LatencyMetric.Observe(time.Since(start).Seconds())
			metrics.StatusMetric.WithLabelValues(strconv.Itoa(resp.Status()), req.Method).Inc()

			// place back the original uri for any later consumers
			req.URL.Path = scope.Path
			req.URL.RawPath = scope.RawPath
		})
	}
}

// RequestIDMiddleware is responsible for adding a request id if none found.
func RequestIDMiddleware(header string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			if v := req.Header.Get(header); v == "" {
				uuid, err := uuid.NewV1()
				if err != nil {
					wrt.WriteHeader(http.StatusInternalServerError)
				}

				req.Header.Set(header, uuid.String())
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// LoggingMiddleware is a custom http logger.
func LoggingMiddleware(
	logger *zap.Logger,
	verbose bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()

			resp, assertOk := w.(middleware.WrapResponseWriter)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			addr := utils.RealIP(req)
			if verbose {
				requestLogger := logger.With(
					zap.Any("headers", req.Header),
					zap.String("path", req.URL.Path),
					zap.String("method", req.Method),
					zap.String("client_ip", addr),
				)
				scope.Logger = requestLogger
			}

			next.ServeHTTP(resp, req)

			if req.URL.Path == req.URL.RawPath || req.URL.RawPath == "" {
				scope.Logger.Info("client request",
					zap.Duration("latency", time.Since(start)),
					zap.Int("status", resp.Status()),
					zap.Int("bytes", resp.BytesWritten()),
					zap.String("remote_addr", req.RemoteAddr),
					zap.String("method", req.Method),
					zap.String("path", req.URL.Path))
			} else {
				scope.Logger.Info("client request",
					zap.Duration("latency", time.Since(start)),
					zap.Int("status", resp.Status()),
					zap.Int("bytes", resp.BytesWritten()),
					zap.String("remote_addr", req.RemoteAddr),
					zap.String("method", req.Method),
					zap.String("path", req.URL.Path),
					zap.String("raw path", req.URL.RawPath))
			}
		})
	}
}

// ResponseHeaderMiddleware is responsible for adding response headers.
func ResponseHeaderMiddleware(headers map[string]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			// @step: inject any custom response headers
			for k, v := range headers {
				wrt.Header().Set(k, v)
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

func DenyMiddleware(
	logger *zap.Logger,
	accessForbidden func(wrt http.ResponseWriter, req *http.Request) context.Context,
) func(http.Handler) http.Handler {
	return func(_ http.Handler) http.Handler {
		logger.Info("enabling the deny middleware")

		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			accessForbidden(wrt, req)
		})
	}
}

// ProxyDenyMiddleware just block everything.
func ProxyDenyMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			ctxVal := req.Context().Value(constant.ContextScopeName)

			var scope *models.RequestScope
			if ctxVal == nil {
				scope = &models.RequestScope{}
			} else {
				var assertOk bool

				scope, assertOk = ctxVal.(*models.RequestScope)
				if !assertOk {
					logger.Error(apperrors.ErrAssertionFailed.Error())
					return
				}
			}

			scope.NoProxy = true
			// update the request context
			ctx := context.WithValue(req.Context(), constant.ContextScopeName, scope)

			next.ServeHTTP(wrt, req.WithContext(ctx))
		})
	}
}

func MethodCheckMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		logger.Info("enabling the method check middleware")

		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			if !utils.IsValidHTTPMethod(req.Method) {
				logger.Warn("method not implemented ", zap.String("method", req.Method))
				wrt.WriteHeader(http.StatusNotImplemented)

				return
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// IdentityHeadersMiddleware is responsible for adding the authentication headers to upstream
//
//nolint:cyclop
func IdentityHeadersMiddleware(
	logger *zap.Logger,
	custom []string,
	cookieAccessName string,
	cookieRefreshName string,
	noProxy bool,
	enableTokenHeader bool,
	enableAuthzHeader bool,
	enableAuthzCookies bool,
	enableHeaderEncoding bool,
	enableIDTokenClaims bool,
	enableUserInfoClaims bool,
) func(http.Handler) http.Handler {
	customClaims := make(map[string]string)

	const minSliceLength int = 1

	cookieFilter := []string{cookieAccessName, cookieRefreshName}

	for _, val := range custom {
		xslices := strings.Split(val, "|")

		val = xslices[0]
		if len(xslices) > minSliceLength {
			customClaims[val] = utils.ToHeader(xslices[1])
		} else {
			customClaims[val] = "X-Auth-" + utils.ToHeader(val)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			var headers http.Header
			if noProxy {
				headers = wrt.Header()
			} else {
				headers = req.Header
			}

			if scope.Identity != nil {
				user := scope.Identity

				const encoding = "UTF-8"
				if enableHeaderEncoding {
//					headers.Set("X-Auth-Audience", mime.BEncoding.Encode(encoding, strings.Join(user.Audiences, ",")))
					headers.Set("X-Auth-Email", mime.BEncoding.Encode(encoding, user.Email))
//					headers.Set("X-Auth-Expiresin", mime.BEncoding.Encode(encoding, user.ExpiresAt.String()))
//					headers.Set("X-Auth-Groups", mime.BEncoding.Encode(encoding, strings.Join(user.Groups, ",")))
					headers.Set("X-Auth-Roles", mime.BEncoding.Encode(encoding, strings.Join(user.Roles, ",")))
//					headers.Set("X-Auth-Subject", mime.BEncoding.Encode(encoding, user.ID))
//					headers.Set("X-Auth-Userid", mime.BEncoding.Encode(encoding, user.Name))
					headers.Set("X-Auth-Username", mime.BEncoding.Encode(encoding, user.Name))
				} else {
//					headers.Set("X-Auth-Audience", strings.Join(user.Audiences, ","))
					headers.Set("X-Auth-Email", user.Email)
//					headers.Set("X-Auth-Expiresin", user.ExpiresAt.String())
//					headers.Set("X-Auth-Groups", strings.Join(user.Groups, ","))
					headers.Set("X-Auth-Roles", strings.Join(user.Roles, ","))
//					headers.Set("X-Auth-Subject", user.ID)
//					headers.Set("X-Auth-Userid", user.Name)
					headers.Set("X-Auth-Username", user.Name)
				}

				// should we add the token header?
				if enableTokenHeader {
					headers.Set("X-Auth-Token", user.RawToken)
				}
				// add the authorization header if requested
				if enableAuthzHeader {
					headers.Set(constant.AuthorizationHeader, "Bearer "+user.RawToken)
				}
				// are we filtering out the cookies
				if !enableAuthzCookies {
					_ = cookie.FilterCookies(req, cookieFilter)
				}
				// inject any custom claims
				for claim, header := range customClaims {
					if claim, found := user.Claims[claim]; found {
						val := fmt.Sprintf("%v", claim)
						if enableHeaderEncoding {
							val = mime.BEncoding.Encode(encoding, val)
						}

						headers.Set(header, val)
					} else {
						headers.Set(header, "")
					}

					if enableIDTokenClaims {
						if claim, found := user.IDTokenClaims[claim]; found {
							val := fmt.Sprintf("%v", claim)
							if enableHeaderEncoding {
								val = mime.BEncoding.Encode(encoding, val)
							}

							headers.Set(header, val)
						}
					}

					if enableUserInfoClaims {
						if claim, found := user.UserInfoClaims[claim]; found {
							val := fmt.Sprintf("%v", claim)
							if enableHeaderEncoding {
								val = mime.BEncoding.Encode(encoding, val)
							}

							headers.Set(header, val)
						}
					}
				}
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// ProxyMiddleware is responsible for handles reverse proxy
// request to the upstream endpoint
//
//nolint:cyclop
func ProxyMiddleware(
	logger *zap.Logger,
	corsOrigins []string,
	headers map[string]string,
	endpoint *url.URL,
	preserveHost bool,
	enableSigningHmac bool,
	encryptionKey string,
	upstream core.ReverseProxy,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(wrt, req)

			// @step: retrieve the request scope
			ctxVal := req.Context().Value(constant.ContextScopeName)

			var scope *models.RequestScope

			if ctxVal != nil {
				var assertOk bool

				scope, assertOk = ctxVal.(*models.RequestScope)
				if !assertOk {
					logger.Error(apperrors.ErrAssertionFailed.Error())
					return
				}

				if scope.AccessDenied || scope.NoProxy {
					return
				}
			}

			// @step: add the proxy forwarding headers
			req.Header.Set(constant.HeaderXRealIP, utils.RealIP(req))

			if xff := req.Header.Get(constant.HeaderXForwardedFor); xff == "" {
				req.Header.Set(constant.HeaderXForwardedFor, utils.RealIP(req))
			}

			if xfh := req.Header.Get(constant.HeaderXForwardedHost); xfh == "" {
				req.Header.Set(constant.HeaderXForwardedHost, req.Host)
			}

			if len(corsOrigins) > 0 {
				// if CORS is enabled by Gatekeeper, do not propagate CORS requests upstream
				req.Header.Del("Origin")
			}
			// @step: add any custom headers to the request
			for k, v := range headers {
				req.Header.Set(k, v)
			}

			// @note: by default goproxy only provides a forwarding proxy,
			// thus all requests have to be absolute and we must update the host headers
			req.URL.Host = endpoint.Host
			req.URL.Scheme = endpoint.Scheme
			// Restore the unprocessed original path, so that we pass upstream exactly what we received
			// as the resource request.
			if scope != nil {
				req.URL.Path = scope.Path
				req.URL.RawPath = scope.RawPath
			}

			if v := req.Header.Get("Host"); v != "" {
				req.Host = v
				req.Header.Del("Host")
			} else if !preserveHost {
				req.Host = endpoint.Host
			}

			if utils.IsUpgradedConnection(req) {
				clientIP := utils.RealIP(req)
				logger.Debug("upgrading the connnection",
					zap.String("client_ip", clientIP),
					zap.String("remote_addr", req.RemoteAddr),
				)

				err := utils.TryUpdateConnection(req, wrt, endpoint)
				if err != nil {
					logger.Error("failed to upgrade connection", zap.Error(err))

					if !errors.Is(err, apperrors.ErrConnectionUpgrade) {
						wrt.WriteHeader(http.StatusInternalServerError)
					}

					return
				}

				return
			}

			if enableSigningHmac {
				reqHmac, err := utils.GenerateHmac(req, encryptionKey)
				if err != nil {
					logger.Error(err.Error())
				}

				req.Header.Set(constant.HeaderXHMAC, reqHmac)
			}

			upstream.ServeHTTP(wrt, req)
		})
	}
}

func ForwardAuthMiddleware(logger *zap.Logger, oAuthURI string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		logger.Info("enabling the forward-auth middleware")

		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			if !strings.Contains(req.URL.Path, oAuthURI) { // this condition is here only because of tests to work
				if forwardedPath := req.Header.Get(constant.HeaderXForwardedURI); forwardedPath != "" {
					req.URL.Path = forwardedPath
					req.URL.RawPath = forwardedPath
				}

				if forwardedMethod := req.Header.Get(constant.HeaderXForwardedMethod); forwardedMethod != "" {
					req.Method = forwardedMethod
				}
			}

			next.ServeHTTP(wrt, req)
		})
	}
}
