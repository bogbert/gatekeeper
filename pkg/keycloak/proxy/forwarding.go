/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxy

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

/*
	proxyMiddleware is responsible for handles reverse proxy
	request to the upstream endpoint
*/
//nolint:cyclop
func proxyMiddleware(
	logger *zap.Logger,
	corsOrigins []string,
	headers map[string]string,
	endpoint *url.URL,
	preserveHost bool,
	upstream reverseProxy,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(wrt, req)

			// @step: retrieve the request scope
			ctxVal := req.Context().Value(constant.ContextScopeName)
			var scope *RequestScope
			if ctxVal != nil {
				var assertOk bool
				scope, assertOk = ctxVal.(*RequestScope)
				if !assertOk {
					logger.Error(apperrors.ErrAssertionFailed.Error())
					return
				}
				if scope.AccessDenied {
					return
				}
			}

			// @step: add the proxy forwarding headers
			req.Header.Set("X-Real-IP", utils.RealIP(req))
			if xff := req.Header.Get(constant.HeaderXForwardedFor); xff == "" {
				req.Header.Set("X-Forwarded-For", utils.RealIP(req))
			} else {
				req.Header.Set("X-Forwarded-For", xff)
			}
			req.Header.Set("X-Forwarded-Host", req.Host)
			req.Header.Set("X-Forwarded-Proto", req.Header.Get("X-Forwarded-Proto"))

			if len(corsOrigins) > 0 {
				// if CORS is enabled by Gatekeeper, do not propagate CORS requests upstream
				req.Header.Del("Origin")
			}
			// @step: add any custom headers to the request
			for k, v := range headers {
				req.Header.Set(k, v)
			}

			// @note: by default goproxy only provides a forwarding proxy, thus all requests have to be absolute and we must update the host headers
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
				if err := utils.TryUpdateConnection(req, wrt, endpoint); err != nil {
					logger.Error("failed to upgrade connection", zap.Error(err))
					wrt.WriteHeader(http.StatusInternalServerError)
					return
				}
				return
			}

			upstream.ServeHTTP(wrt, req)
		})
	}
}

// forwardProxyHandler is responsible for signing outbound requests
func forwardProxyHandler(
	logger *zap.Logger,
	pat *PAT,
	rpt *RPT,
	enableUma bool,
	forwardingDomains []string,
	enableHmac bool,
	encryptionKey string,
) func(*http.Request, *http.Response) {
	return func(req *http.Request, resp *http.Response) {
		var token string

		pat.m.RLock()
		token = pat.Token.AccessToken
		pat.m.RUnlock()

		if rpt != nil && enableUma {
			rpt.m.RLock()
			umaToken := rpt.Token
			rpt.m.RUnlock()
			req.Header.Set(constant.UMAHeader, umaToken)
		}

		hostname := req.Host
		req.URL.Host = hostname
		// is the host being signed?
		if len(forwardingDomains) == 0 || utils.ContainsSubString(hostname, forwardingDomains) {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			req.Header.Set("X-Forwarded-Agent", constant.Prog)
		}
		if enableHmac {
			reqHmac, err := utils.GenerateHmac(req, encryptionKey)
			if err != nil {
				logger.Error(err.Error())
			}
			req.Header.Set(constant.HeaderXHMAC, reqHmac)
		}
	}
}
