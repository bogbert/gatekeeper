package externalidp

import (
	"regexp"
	"sync"
	"time"
)

// KeycloakUser represents a user from Keycloak export.
type KeycloakUser struct {
	ID                string         `json:"id"`
	Username          string         `json:"username"`
	PreferredUsername string         `json:"preferred_username"`
	Email             string         `json:"email"`
	Name              string         `json:"name"`
	Roles             []string       `json:"roles"`
	Groups            []string       `json:"groups"`
	Audiences         []string       `json:"audiences"`
	Acr               string         `json:"acr"`
	Tag               string         `json:"tag"`
	Claims            map[string]any `json:"claims"`
}

// UsersData represents the JSON file structure.
type UsersData struct {
	Users       []KeycloakUser `json:"users"`
	GeneratedAt time.Time      `json:"generated_at"`
	Version     string         `json:"version"`
}

// UserCache provides thread-safe access to user data.
type UserCache struct {
	mu              sync.RWMutex
	usersByUsername map[string]*KeycloakUser
	usersByEmail    map[string]*KeycloakUser
	data            *UsersData
	lastModTime     time.Time
	config          *Config
	filterRegex     *regexp.Regexp
}
