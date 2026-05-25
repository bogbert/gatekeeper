package externalidp

import (
	"fmt"
	"regexp"
	"time"

	"go.uber.org/zap"
)

// NewUserCache creates a new user cache.
func NewUserCache(config *Config, logger *zap.Logger) (*UserCache, error) {
	cache := &UserCache{
		usersByUsername: make(map[string]*KeycloakUser),
		usersByEmail:    make(map[string]*KeycloakUser),
		config:          config,
	}

	// Compile regex only if filter is set and is regex
	if config.UserFilter != "" && config.UserFilterIsRegex {
		regex, err := regexp.Compile(config.UserFilter)
		if err != nil {
			return nil, fmt.Errorf("invalid user filter regex: %w", err)
		}

		cache.filterRegex = regex
	}

	if err := cache.Reload(logger); err != nil {
		return nil, fmt.Errorf("initial load failed: %w", err)
	}

	return cache, nil
}

// Reload reloads the user data from file.
func (uc *UserCache) Reload(logger *zap.Logger) error {
	modTime, err := GetFileModTime(uc.config.UsersFilePath)
	if err != nil {
		return err
	}

	// Check if file has been modified
	if !uc.lastModTime.IsZero() && !modTime.After(uc.lastModTime) {
		return nil // No changes
	}

	data, err := LoadUsersFromFile(uc.config.UsersFilePath)
	if err != nil {
		return err
	}

	// Build new indexes
	newUsersByUsername := make(map[string]*KeycloakUser)
	newUsersByEmail := make(map[string]*KeycloakUser)
	filteredCount := 0

	for i := range data.Users {
		user := &data.Users[i]

		// Apply client filter
		if !uc.matchesClientFilter(user) {
			continue
		}

		filteredCount++

		if user.Username != "" {
			newUsersByUsername[user.Username] = user
		}

		if user.Email != "" {
			newUsersByEmail[user.Email] = user
		}
	}

	// Atomic swap
	uc.mu.Lock()
	uc.data = data
	uc.usersByUsername = newUsersByUsername
	uc.usersByEmail = newUsersByEmail
	uc.lastModTime = modTime
	uc.mu.Unlock()

	logger.Info("external IDP users cache reloaded",
		zap.Int("total_users", len(data.Users)),
		zap.Int("filtered_users", filteredCount),
		zap.Time("file_mod_time", modTime),
	)

	return nil
}

// matchesClientFilter checks if the user's tag matches the filter.
func (uc *UserCache) matchesClientFilter(user *KeycloakUser) bool {
	// If no filter configured, accept all users
	if uc.config.UserFilter == "" {
		return true
	}

	tagValue := user.Tag

	// If filter is regex
	if uc.config.UserFilterIsRegex {
		return uc.filterRegex.MatchString(tagValue)
	}

	// Literal match
	return tagValue == uc.config.UserFilter
}

// FindUser searches for a user by the configured match field.
func (uc *UserCache) FindUser(matchValue string, matchField string) (*KeycloakUser, error) {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	var user *KeycloakUser
	var found bool

	switch matchField {
	case "username":
		user, found = uc.usersByUsername[matchValue]
	case "email":
		user, found = uc.usersByEmail[matchValue]
	default:
		return nil, fmt.Errorf("unsupported match field: %s", matchField)
	}

	if !found {
		return nil, fmt.Errorf("user not found for %s: %s", matchField, matchValue)
	}

	return user, nil
}

// StartAutoReload starts a background goroutine to periodically reload the file.
func (uc *UserCache) StartAutoReload(logger *zap.Logger, stopCh <-chan struct{}) {
	ticker := time.NewTicker(uc.config.FileReloadInterval)
	defer ticker.Stop()

	logger.Info("starting auto-reload for external IDP users file",
		zap.Duration("interval", uc.config.FileReloadInterval),
		zap.String("file_path", uc.config.UsersFilePath),
	)

	for {
		select {
		case <-ticker.C:
			if err := uc.Reload(logger); err != nil {
				logger.Error("failed to reload external IDP users file", zap.Error(err))
			}
		case <-stopCh:
			logger.Info("stopping external IDP users file auto-reload")
			return
		}
	}
}
