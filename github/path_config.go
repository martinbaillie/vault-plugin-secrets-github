package github

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathPatternConfig is the string used to define the base path of the config
// endpoint as well as the storage path of the config object.
const pathPatternConfig = "config"

const (
	errConfMarshal = Error("failed to marshal configuration to JSON")
	errConfPersist = Error("failed to persist configuration to storage")
	errConfDelete  = Error("failed to delete configuration from storage")
)

const (
	keyAppID                     = "app_id"
	descAppID                    = "Application ID of the GitHub App."
	keyPrvKey                    = "prv_key"
	includeRepositoryMetadataKey = "include_repository_metadata"

	descPrvKey                       = "Private key for signing GitHub access token requests (JWTs)."
	descIncludeRepositoryMetadataKey = "If set to true, the token lease response 'data.repositories' sub-field will be minimized to 'data.repositories.*.names'"
	keyBaseURL                       = "base_url"
	descBaseURL                      = "Base URL for API requests (defaults to the public GitHub API)."
)

const pathConfigHelpSyn = `
Configure the GitHub secrets plugin.
`

var pathConfigHelpDesc = fmt.Sprintf(`
Configure the GitHub secrets plugin using the above parameters.

NOTE: %q must be in PEM PKCS#1 RSAPrivateKey format.`, keyPrvKey)

// pathConfig defines the /github/config base path on the backend.
func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternConfig,
		Fields: map[string]*framework.FieldSchema{
			keyAppID: {
				Type:        framework.TypeInt,
				Description: descAppID,
				Required:    true,
			},
			keyPrvKey: {
				Type:        framework.TypeString,
				Description: descPrvKey,
				Required:    true,
			},
			includeRepositoryMetadataKey: {
				Type:        framework.TypeBool,
				Description: descIncludeRepositoryMetadataKey,
				Required:    false,
				Default:     true,
			},
			keyBaseURL: {
				Type:        framework.TypeString,
				Description: descBaseURL,
			},
		},
		ExistenceCheck: b.pathConfigExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigWrite),
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigRead),
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigWrite),
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigDelete),
			},
		},
		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

// pathConfigRead corresponds to READ on /github/config.
func (b *backend) pathConfigRead(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	c, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	resData := map[string]any{
		keyAppID:                     c.AppID,
		keyBaseURL:                   c.BaseURL,
		includeRepositoryMetadataKey: c.IncludeRepositoryMetadata,
	}

	// We don't return the key but indicate its presence for a better UX.
	if c.PrvKey != "" {
		resData[keyPrvKey] = "<configured>"
	} else {
		resData[keyPrvKey] = "" // Vault renders this as "n/a" which is ideal.
	}

	return &logical.Response{Data: resData}, nil
}

// pathConfigWrite corresponds to both CREATE and UPDATE on /github/config.
func (b *backend) pathConfigWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	c, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Update the configuration.
	changed, err := c.Update(d)
	if err != nil {
		return nil, logical.CodedError(400, err.Error())
	}

	// Persist only if changed.
	if changed {
		var entry *logical.StorageEntry

		if entry, err = logical.StorageEntryJSON(pathPatternConfig, c); err != nil {
			// NOTE: Failure scenario cannot happen.
			return nil, fmt.Errorf("%s: %w", errConfMarshal, err)
		}

		if err = req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("%s: %w", errConfPersist, err)
		}

		// Invalidate existing client so it reads the new configuration.
		b.Invalidate(ctx, pathPatternConfig)
	}

	return nil, nil
}

// pathConfigDelete corresponds to DELETE on /github/config.
func (b *backend) pathConfigDelete(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, pathPatternConfig); err != nil {
		return nil, fmt.Errorf("%s: %w", errConfDelete, err)
	}

	// Invalidate existing client so it reads the new configuration.
	b.Invalidate(ctx, pathPatternConfig)

	return nil, nil
}

// pathConfigExistenceCheck is implemented on this path to avoid breaking user
// backwards compatibility. The CreateOperation will likely be removed in a
// future major version of the plugin.
func (b *backend) pathConfigExistenceCheck(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (bool, error) {
	entry, err := req.Storage.Get(ctx, pathPatternConfig)
	if err != nil {
		return false, fmt.Errorf("%s: %w", errConfRetrieval, err)
	}

	return entry != nil && len(entry.Value) > 0, nil
}
