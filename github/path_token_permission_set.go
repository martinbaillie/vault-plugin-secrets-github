package github

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/prometheus/client_golang/prometheus"
)

// pathPatternToken is the string used to define the base path of the token
// endpoint.
//
//nolint:gosec // false positive.
const pathTokenPermissionSetHelpSyn = `
Create and return a token using the GitHub secrets plugin.
`

var pathTokenPermissinonSetHelpDesc = fmt.Sprintf(`
Create and return a token using the GitHub secrets plugin.

NOTE: %q is an installation ID and '%s' is an organization name. You can
provide either or both. If both, installation ID will take precedence because
organization name results in an additional round trip to GitHub to discover the
installation ID. Latency sensitive users should favour installation IDs.

Optionally, the token can be constrained by the following parameters:

* %q is a slice of repository names.
These must be the short names of repositories under the organization.

* %q is a slice of repository IDs.
The quickest way to find a repository ID: https://stackoverflow.com/a/47223479

* %q is a map of permission names to their access type (read or write).

Permission names taken from: https://developer.github.com/v3/apps/permissions
`, keyInstallationID, keyOrgName, keyRepos, keyRepoIDs, keyPerms)

func (b *backend) pathTokenPermissionSet() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s/%s", pathPatternToken, framework.GenericNameRegex("permissionset")),
		Fields: map[string]*framework.FieldSchema{
			"permissionset": {
				Type:        framework.TypeString,
				Description: "Required. Name of the permission set.",
			},
		},
		ExistenceCheck: b.pathTokenPermissionSetExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			// As per the issue request in https://git.io/JUhRk, allow Vault
			// Reads (i.e. HTTP GET) to also write the GitHub tokens.
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathTokenPermissionSetWrite),
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathTokenPermissionSetWrite),
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathTokenPermissionSetWrite),
			},
		},
		HelpSynopsis:    pathTokenPermissionSetHelpSyn,
		HelpDescription: pathTokenPermissinonSetHelpDesc,
	}
}

// pathTokenWrite corresponds to READ, CREATE and UPDATE on /github/token.
func (b *backend) pathTokenPermissionSetWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (res *logical.Response, err error) {
	client, done, err := b.Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	defer done()

	psName := d.Get("permissionset").(string)

	ps, _ := getPermissionSet(ctx, psName, req.Storage)
	if ps == nil {
		return logical.ErrorResponse("permission set '%s' does not exist", psName), nil
	}

	opts := ps.TokenRequest

	// Instrument and log the token API call, recording status, duration and
	// whether any constraints (permissions, repositories, repository IDs) were
	// requested.
	defer func(begin time.Time) {
		duration := time.Since(begin)
		b.Logger().Debug("attempted to create a new installation token",
			"took", duration.String(),
			"err", err,
			"permissions", opts.Permissions,
			"org_name", opts.OrgName,
			"installation_id", fmt.Sprint(opts.InstallationID),
			"repository_ids", fmt.Sprint(opts.RepositoryIDs),
			"repositories", fmt.Sprint(opts.Repositories),
		)
		requestDuration.With(prometheus.Labels{
			"success":         strconv.FormatBool(err == nil),
			keyOrgName:        opts.OrgName,
			keyInstallationID: fmt.Sprint(opts.InstallationID),
			keyPerms:          strconv.FormatBool(len(opts.Permissions) > 0),
			keyRepoIDs:        strconv.FormatBool(len(opts.RepositoryIDs) > 0),
			keyRepos:          strconv.FormatBool(len(opts.Repositories) > 0),
		}).Observe(duration.Seconds())
	}(time.Now())

	// Perform the token request.
	return client.Token(ctx, opts)
}

// pathTokenPermissionSetExistenceCheck always returns false to force the Create
// path. This plugin predates the framework's 'ExistenceCheck' features and we
// wish to avoid changing any contracts with the user at this stage. Tokens are
// created regardless of whether the request is a CREATE, UPDATE or even READ
// (per a user's request (https://git.io/JUhRk).
func (b *backend) pathTokenPermissionSetExistenceCheck(
	context.Context, *logical.Request, *framework.FieldData,
) (bool, error) {
	return false, nil
}
