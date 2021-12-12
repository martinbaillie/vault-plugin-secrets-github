package github

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = `
GitHub Apps Token Backend
`

const backendSecretType = "github_token"

const (
	fmtErrConfRetrieval = "failed to get configuration from storage"
	fmtErrConfUnmarshal = "failed to unmarshal configuration from JSON"
	fmtErrClientCreate  = "failed to create an authenticated GitHub client"
)

var errBackendConfigNil = errors.New("backend configuration was nil")

type backend struct {
	*framework.Backend

	// The actual GitHub client and a lock used for controlling access allowing
	// for safe rotation if the mounted configuration changes.
	client     *Client
	clientLock sync.RWMutex

	permissionsetLock sync.Mutex
}

// Factory creates a configured logical.Backend for the GitHub plugin.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := new(backend)

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{pathPatternInfo, pathPatternMetrics},
		},
		Paths: []*framework.Path{
			b.pathInfo(),
			b.pathMetrics(),
			b.pathConfig(),
			b.pathToken(),
			b.pathTokenPermissionSet(),
			b.pathPermissionSet(),
			b.pathPermissionSetList(),
		},
		Secrets: []*framework.Secret{{
			Type: backendSecretType,
			Fields: map[string]*framework.FieldSchema{
				"token": {
					Type:        framework.TypeString,
					Description: "GitHub token.",
				},
			},
			// Allow explicit GitHub token revocation via the Vault lease API.
			Revoke: b.Revoke,
			// NOTE: Unfortunately GitHub has no mechanism for renewing tokens.
			// Renew:
		}},
		Invalidate: b.Invalidate,
	}

	if conf == nil {
		return nil, errBackendConfigNil
	}

	if err := b.Setup(ctx, conf); err != nil {
		// NOTE: Setup never errors in current Hashicorp SDK.
		return nil, err
	}

	b.Logger().Info("plugin backend successfully initialised")

	return b, nil
}

// Invalidate resets the plugin. It is called when a key is updated via
// replication.
func (b *backend) Invalidate(_ context.Context, key string) {
	if key == pathPatternConfig {
		// Configuration has changed so reset the client.
		b.clientLock.Lock()
		b.client = nil
		b.clientLock.Unlock()
	}
}

// Config parses and returns the configuration data from the storage backend. An
// empty config is returned in the case where there is no existing in storage.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*Config, error) {
	c := NewConfig()

	entry, err := s.Get(ctx, pathPatternConfig)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fmtErrConfRetrieval, err)
	}

	if entry == nil || len(entry.Value) == 0 {
		return c, nil
	}

	if err := entry.DecodeJSON(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", fmtErrConfUnmarshal, err)
	}

	return c, nil
}

// Client returns a client for interfacing the configured GitHub App. Resets due
// to configuration updates are safely handled. Users are expected to use the
// returned closer when finished.
func (b *backend) Client(s logical.Storage) (*Client, func(), error) {
	b.clientLock.RLock()
	if b.client != nil {
		return b.client, func() { b.clientLock.RUnlock() }, nil
	}
	b.clientLock.RUnlock()

	// Acquire a globally exclusive lock to close any connections and create a
	// new client.
	//
	// NOTE: Since all invocations of this method acquire a read lock and defer
	// release, this will block until all clients are no longer in use.
	b.clientLock.Lock()

	// Clear the client once more in case of earlier concurrent creation.
	b.client = nil

	config, err := b.Config(context.Background(), s)
	if err != nil {
		b.clientLock.Unlock()

		return nil, nil, err
	}

	client, err := NewClient(config)
	if err != nil {
		b.clientLock.Unlock()

		return nil, nil, fmt.Errorf("%s: %w", fmtErrClientCreate, err)
	}

	b.client = client

	b.clientLock.Unlock()
	b.Logger().Debug("created GitHub App installation client",
		"base_url", config.BaseURL,
		"app_id", strconv.Itoa(config.AppID),
		"ins_id", strconv.Itoa(config.InsID),
		"org_name", config.OrgName,
	)
	b.clientLock.RLock()

	return b.client, func() { b.clientLock.RUnlock() }, nil
}
