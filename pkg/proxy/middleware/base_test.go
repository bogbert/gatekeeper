package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/middleware"
	"go.uber.org/zap"
)

func TestUnreservedPercentEncodingIsDecodedForMatching(t *testing.T) {
	r := chi.NewRouter()
	r.Use(middleware.EntrypointMiddleware(zap.NewNop(), "/oauth"))

	hit := false
	r.Handle("/joblauncher*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hit = true
	}))

	req := httptest.NewRequest("GET", "/%6aoblauncher/files/", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	if !hit {
		t.Fatal("resource rule for /joblauncher* was bypassed via percent-encoding of an unreserved character")
	}
}

func TestReservedPercentEncodingIsNotDecodedForMatching(t *testing.T) {
	r := chi.NewRouter()
	r.Use(middleware.EntrypointMiddleware(zap.NewNop(), "/oauth"))

	var strictHit, looseHit bool

	// A stricter resource whose match depends on a *real* path separator.
	r.Handle("/secure/admin/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		strictHit = true
	}))
	// A looser catch-all for anything under /secure that isn't /secure/admin/*.
	r.Handle("/secure/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		looseHit = true
	}))

	// "%2F" here must NOT be treated as a literal "/" - otherwise this
	// would be silently promoted from the loose rule to the strict one
	// (or vice versa, depending on rule shape), which is exactly the kind
	// of rule confusion RFC 3986 warns against for reserved characters.
	req := httptest.NewRequest("GET", "/secure/admin%2Fsecret", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	t.Logf("strictHit=%v looseHit=%v", strictHit, looseHit)

	if strictHit {
		t.Fatal("an encoded '%2F' was treated as a literal path separator, " +
			"causing the request to match a different (stricter) resource rule than the literal string warrants")
	}

	if !looseHit {
		t.Fatal("expected the request to fall through to the /secure/* rule since %2F must stay opaque")
	}
}

func TestObfuscatedOAuthPathIsRecognizedViaFullDecoding(t *testing.T) {
	r := chi.NewRouter()
	r.Use(middleware.EntrypointMiddleware(zap.NewNop(), "/oauth"))

	var oauthHit, fallbackHit bool

	r.Handle("/oauth/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		oauthHit = true
	}))
	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fallbackHit = true
	}))

	// "%2F" would stay opaque under the strict (user resource rule) decoding
	// path, so "/oauth%2Ftest" would never reduce to "/oauth/test" and would
	// fall through to the catch-all. Gatekeeper's own control-plane prefix
	// must still be recognized here via full decoding, exactly like it was
	// before user resource rules needed the stricter behavior.
	req := httptest.NewRequest("GET", "/oauth%2Ftest", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	t.Logf("oauthHit=%v fallbackHit=%v", oauthHit, fallbackHit)

	if !oauthHit {
		t.Fatal("obfuscated request for the internal /oauth control-plane prefix was not recognized")
	}

	if fallbackHit {
		t.Fatal("obfuscated /oauth request incorrectly fell through to the catch-all resource rule")
	}
}
