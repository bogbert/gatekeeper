package core

import (
	"os"
	"testing"

	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
)

const (
	GrantTypeAuthCode     = "authorization_code"
	GrantTypeUserCreds    = "password"
	GrantTypeRefreshToken = "refresh_token"
	GrantTypeClientCreds  = "client_credentials"
	GrantTypeUmaTicket    = "urn:ietf:params:oauth:grant-type:uma-ticket"
)

type OpenIDProviderRetryCount int

type Configs interface {
	ReadConfigFile(string) error
	IsValid() error
	GetResources() []*authorization.Resource
	SetResources([]*authorization.Resource)
	GetHeaders() map[string]string
	GetMatchClaims() map[string]string
	GetTags() map[string]string
	GetAllowedQueryParams() map[string]string
	GetDefaultAllowedQueryParams() map[string]string
}

type CommonConfig struct{}

func WriteFakeConfigFile(t *testing.T, content string) *os.File {
	file, err := os.CreateTemp("", "node_label_file")
	if err != nil {
		t.Fatalf("unexpected error creating node_label_file: %v", err)
	}
	file.Close()

	if err := os.WriteFile(file.Name(), []byte(content), 0600); err != nil {
		t.Fatalf("unexpected error writing node label file: %v", err)
	}

	return file
}
