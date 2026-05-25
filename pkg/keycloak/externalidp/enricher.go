package externalidp

import (
	"fmt"

	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"go.uber.org/zap"
)

// Enricher handles the enrichment of tokens with Keycloak claims.
type Enricher struct {
	cache  *UserCache
	config *Config
}

// NewEnricher creates a new enricher.
func NewEnricher(cache *UserCache, config *Config) *Enricher {
	return &Enricher{
		cache:  cache,
		config: config,
	}
}

// ShouldEnrich determines if enrichment should be applied.
func (e *Enricher) ShouldEnrich() bool {
	return e.config.Enabled
}

// EnrichIdentity enriches user identity with Keycloak claims.
func (e *Enricher) EnrichIdentity(
	identity *models.UserContext,
	logger *zap.Logger,
) (*models.UserContext, error) {
	// Extract the match value from the external token claims
	matchValue, err := e.extractMatchValue(identity)
	if err != nil {
		return nil, fmt.Errorf("failed to extract match value: %w", err)
	}

	logger.Debug("attempting to enrich identity",
		zap.String("match_field", e.config.UsersFileMatchField),
		zap.String("match_value", matchValue),
	)

	// Find the corresponding Keycloak user
	kcUser, err := e.cache.FindUser(matchValue, e.config.UsersFileMatchField)
	if err != nil {
		return nil, fmt.Errorf("user lookup failed: %w", err)
	}

	logger.Debug("found matching Keycloak user",
		zap.String("username", kcUser.Username),
		zap.String("email", kcUser.Email),
		zap.String("id", kcUser.ID),
	)

	preferredName := kcUser.PreferredUsername
	if preferredName == "" {
		preferredName = kcUser.Email
	}

	// Create enriched identity
	enriched := &models.UserContext{
		ID:            kcUser.ID,
		Name:          preferredName,
		Email:         kcUser.Email,
		PreferredName: preferredName,
		Roles:         kcUser.Roles,
		Groups:        kcUser.Groups,
		Audiences:     kcUser.Audiences,
		Acr:           kcUser.Acr,
		RawToken:      identity.RawToken,
		ExpiresAt:     identity.ExpiresAt,
		BearerToken:   identity.BearerToken,
		Permissions:   identity.Permissions,
		Claims:        make(map[string]any),
	}

	// Copy all Keycloak claims
	for k, v := range kcUser.Claims {
		enriched.Claims[k] = v
	}

	// Add standard claims
	enriched.Claims["sub"] = kcUser.ID
	enriched.Claims["preferred_username"] = preferredName
	enriched.Claims["username"] = kcUser.Username
	enriched.Claims["email"] = kcUser.Email
	enriched.Claims["roles"] = kcUser.Roles

	if kcUser.Name != "" {
		enriched.Claims["name"] = kcUser.Name
	}

	if len(kcUser.Groups) > 0 {
		enriched.Claims["groups"] = kcUser.Groups
	}

	if kcUser.Acr != "" {
		enriched.Claims["acr"] = kcUser.Acr
	}

	return enriched, nil
}

// extractMatchValue extracts the match value from external token.
func (e *Enricher) extractMatchValue(identity *models.UserContext) (string, error) {
	// Try to get the value from claims
	if val, ok := identity.Claims[e.config.ExternalMatchClaim]; ok {
		return fmt.Sprintf("%v", val), nil
	}

	// Fallback to standard fields
	switch e.config.ExternalMatchClaim {
	case "preferred_username", "username":
		if identity.PreferredName != "" {
			return identity.PreferredName, nil
		}

		if identity.Name != "" {
			return identity.Name, nil
		}
	case "email":
		if identity.Email != "" {
			return identity.Email, nil
		}
	case "sub", "subject":
		if identity.ID != "" {
			return identity.ID, nil
		}
	}

	return "", fmt.Errorf(
		"match claim '%s' not found in token",
		e.config.ExternalMatchClaim,
	)
}
