package externalidp

import (
	"time"
)

// Config holds configuration for external IDP enrichment.
type Config struct {
	Enabled             bool
	UsersFilePath       string
	ExternalMatchClaim  string
	UsersFileMatchField string
	UserFilter          string
	UserFilterIsRegex   bool
	FileReloadInterval  time.Duration
}

// NewConfig creates a new Config from application config values.
func NewConfig(
	enabled bool,
	usersFilePath string,
	externalMatchClaim string,
	usersFileMatchField string,
	userFilter string,
	userFilterIsRegex bool,
	fileReloadInterval time.Duration,
) *Config {
	return &Config{
		Enabled:             enabled,
		UsersFilePath:       usersFilePath,
		ExternalMatchClaim:  externalMatchClaim,
		UsersFileMatchField: usersFileMatchField,
		UserFilter:          userFilter,
		UserFilterIsRegex:   userFilterIsRegex,
		FileReloadInterval:  fileReloadInterval,
	}
}
