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
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v12"
	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	configcore "github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

//nolint:cyclop
func getPAT(
	logger *zap.Logger,
	pat *PAT,
	clientID string,
	clientSecret string,
	realm string,
	openIDProviderTimeout time.Duration,
	patRetryCount int,
	patRetryInterval time.Duration,
	enableForwarding bool,
	forwardingGrantType string,
	idpClient *gocloak.GoCloak,
	forwardingUsername string,
	forwardingPassword string,
	done chan bool,
) {
	retry := 0
	initialized := false
	grantType := configcore.GrantTypeClientCreds

	if enableForwarding && forwardingGrantType == configcore.GrantTypeUserCreds {
		grantType = configcore.GrantTypeUserCreds
	}

	for {
		if retry > 0 {
			logger.Info(
				"retrying fetching PAT token",
				zap.Int("retry", retry),
			)
		}

		ctx, cancel := context.WithTimeout(
			context.Background(),
			openIDProviderTimeout,
		)

		var token *gocloak.JWT
		var err error

		switch grantType {
		case configcore.GrantTypeClientCreds:
			token, err = idpClient.LoginClient(
				ctx,
				clientID,
				clientSecret,
				realm,
			)
		case configcore.GrantTypeUserCreds:
			token, err = idpClient.Login(
				ctx,
				clientID,
				clientSecret,
				realm,
				forwardingUsername,
				forwardingPassword,
			)
		default:
			logger.Error(
				"Chosen grant type is not supported",
				zap.String("grant_type", grantType),
			)
			os.Exit(11)
		}

		if err != nil {
			retry++
			logger.Error("problem getting PAT token", zap.Error(err))

			if retry >= patRetryCount {
				cancel()
				os.Exit(10)
			}

			<-time.After(patRetryInterval)
			continue
		}

		pat.m.Lock()
		pat.Token = token
		pat.m.Unlock()

		if !initialized {
			done <- true
		}

		initialized = true

		parsedToken, err := jwt.ParseSigned(token.AccessToken)
		if err != nil {
			retry++
			logger.Error("failed to parse the access token", zap.Error(err))
			<-time.After(patRetryInterval)
			continue
		}

		stdClaims := &jwt.Claims{}
		err = parsedToken.UnsafeClaimsWithoutVerification(stdClaims)
		if err != nil {
			retry++
			logger.Error("unable to parse access token for claims", zap.Error(err))
			<-time.After(patRetryInterval)
			continue
		}

		retry = 0
		expiration := stdClaims.Expiry.Time()
		refreshIn := utils.GetWithin(expiration, 0.85)

		logger.Info(
			"waiting for expiration of access token",
			zap.Float64("refresh_in", refreshIn.Seconds()),
		)

		<-time.After(refreshIn)
	}
}

func WithUMAIdentity(
	req *http.Request,
	targetPath string,
	user *models.UserContext,
	cookieUMAName string,
	provider *oidc3.Provider,
	clientID string,
	skipClientIDCheck bool,
	skipIssuerCheck bool,
	getIdentity func(req *http.Request, tokenCookie string, tokenHeader string) (*models.UserContext, error),
	authzFunc func(targetPath string, userPerms models.Permissions) (authorization.AuthzDecision, error),
) (authorization.AuthzDecision, error) {
	umaUser, err := getIdentity(req, cookieUMAName, constant.UMAHeader)
	if err != nil {
		return authorization.DeniedAuthz, err
	}

	// make sure somebody doesn't sent one user access token
	// and others user valid uma token in one request
	if umaUser.ID != user.ID {
		return authorization.DeniedAuthz, apperrors.ErrAccessMismatchUmaToken
	}

	_, err = utils.VerifyToken(
		req.Context(),
		provider,
		umaUser.RawToken,
		clientID,
		skipClientIDCheck,
		skipIssuerCheck,
	)
	if err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return authorization.DeniedAuthz, apperrors.ErrUMATokenExpired
		}
		return authorization.DeniedAuthz, err
	}

	return authzFunc(targetPath, umaUser.Permissions)
}

// getRPT retrieves relaying party token
func getRPT(
	ctx context.Context,
	pat *PAT,
	idpClient *gocloak.GoCloak,
	realm string,
	targetPath string,
	userToken string,
	methodScope *string,
) (*gocloak.JWT, error) {
	matchingURI := true
	resourceParam := gocloak.GetResourceParams{
		URI:         &targetPath,
		MatchingURI: &matchingURI,
		Scope:       methodScope,
	}

	pat.m.RLock()
	patTok := pat.Token.AccessToken
	pat.m.RUnlock()

	resources, err := idpClient.GetResourcesClient(
		ctx,
		patTok,
		realm,
		resourceParam,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%s %s",
			apperrors.ErrNoIDPResourceForPath.Error(),
			err,
		)
	}

	if len(resources) == 0 {
		return nil, apperrors.ErrNoIDPResourceForPath
	}
	if len(resources) > 1 {
		return nil, apperrors.ErrTooManyResources
	}

	resourceID := resources[0].ID
	resourceScopes := make([]string, 0)
	if len(*resources[0].ResourceScopes) == 0 {
		return nil, fmt.Errorf(
			"%w, resource: %s",
			apperrors.ErrMissingScopesForResource,
			*resourceID,
		)
	}

	if methodScope != nil {
		resourceScopes = append(resourceScopes, *methodScope)
	} else {
		for _, scope := range *resources[0].ResourceScopes {
			resourceScopes = append(resourceScopes, *scope.Name)
		}
	}

	permissions := []gocloak.CreatePermissionTicketParams{
		{
			ResourceID:     resourceID,
			ResourceScopes: &resourceScopes,
		},
	}

	permTicket, err := idpClient.CreatePermissionTicket(
		ctx,
		patTok,
		realm,
		permissions,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%s resource: %s %w",
			apperrors.ErrPermissionTicketForResourceID.Error(),
			*resourceID,
			err,
		)
	}

	grantType := configcore.GrantTypeUmaTicket

	rptOptions := gocloak.RequestingPartyTokenOptions{
		GrantType: &grantType,
		Ticket:    permTicket.Ticket,
	}

	if userToken == "" {
		userToken = patTok
	}

	rpt, err := idpClient.GetRequestingPartyToken(ctx, userToken, realm, rptOptions)
	if err != nil {
		return nil, fmt.Errorf(
			"%s resource: %s %w",
			apperrors.ErrRetrieveRPT.Error(),
			*resourceID,
			err,
		)
	}

	return rpt, nil
}

func refreshUmaToken(
	ctx context.Context,
	pat *PAT,
	idpClient *gocloak.GoCloak,
	realm string,
	targetPath string,
	user *models.UserContext,
	methodScope *string,
) (*models.UserContext, error) {
	tok, err := getRPT(
		ctx,
		pat,
		idpClient,
		realm,
		targetPath,
		user.RawToken,
		methodScope,
	)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseSigned(tok.AccessToken)
	if err != nil {
		return nil, err
	}

	umaUser, err := session.ExtractIdentity(token)
	if err != nil {
		return nil, err
	}

	umaUser.RawToken = tok.AccessToken
	return umaUser, nil
}
