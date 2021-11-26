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
	fmtErrConfMarshal = "failed to marshal configuration to JSON"
	fmtErrConfPersist = "failed to persist configuration to storage"
	fmtErrConfDelete  = "failed to delete configuration from storage"
)

const (
	keyAppID    = "app_id"
	descAppID   = "Application ID of the GitHub App."
	keyInsID    = "ins_id"
	descInsID   = "Installation ID of the GitHub App."
	keyOrgName  = "org_name"
	descOrgName = "Organization name for the GitHub App."
	keyPrvKey   = "prv_key"
	descPrvKey  = "Private key for signing GitHub access token requests (JWTs)."
	keyBaseURL  = "base_url"
	descBaseURL = "Base URL for API requests (defaults to the public GitHub API)."
)

const pathConfigHelpSyn = `
Configure the GitHub secrets plugin.
`

var pathConfigHelpDesc = fmt.Sprintf(`
Configure the GitHub secrets plugin using the above parameters.

NOTE: '%s' must be in PEM PKCS#1 RSAPrivateKey format.`, keyPrvKey)

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
			keyInsID: {
				Type:        framework.TypeInt,
				Description: descInsID,
			},
			keyOrgName: {
				Type:        framework.TypeString,
				Description: descOrgName,
			},
			keyPrvKey: {
				Type:        framework.TypeString,
				Description: descPrvKey,
				Required:    true,
			},
			keyBaseURL: {
				Type:        framework.TypeString,
				Description: descBaseURL,
			},
		},
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

	return &logical.Response{
		Data: map[string]interface{}{
			keyAppID:   c.AppID,
			keyInsID:   c.InsID,
			keyOrgName: c.OrgName,
			keyBaseURL: c.BaseURL,
		},
	}, nil
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
		entry, err := logical.StorageEntryJSON(pathPatternConfig, c)
		if err != nil {
			// NOTE: Failure scenario cannot happen.
			return nil, fmt.Errorf("%s: %w", fmtErrConfMarshal, err)
		}

		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("%s: %w", fmtErrConfPersist, err)
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
		return nil, fmt.Errorf("%s: %w", fmtErrConfDelete, err)
	}

	// Invalidate existing client so it reads the new configuration.
	b.Invalidate(ctx, pathPatternConfig)

	return nil, nil
}
