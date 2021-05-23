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
const pathTokenPermissionSetHelpSyn = `
Create and return a token using the GitHub secrets plugin.
`

var pathTokenPermissinonSetHelpDesc = fmt.Sprintf(`
Create and return a token using the GitHub secrets plugin, optionally
constrained by the above parameters.

NOTE: '%s' is a slice of repository names.
These must be the short names of repositories under the organisation.

NOTE: '%s' is a slice of repository IDs.
The quickest way to find a repository ID: https://stackoverflow.com/a/47223479

NOTE: '%s' is a map of permission names to their access type (read or write).
Permission names taken from: https://developer.github.com/v3/apps/permissions
`, keyRepos, keyRepoIDs, keyPerms)

func (b *backend) pathTokenPermissionSet() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s/%s", pathPatternToken, framework.GenericNameRegex("permissionset")),
		Fields: map[string]*framework.FieldSchema{
			"permissionset": {
				Type:        framework.TypeString,
				Description: "Required. Name of the permission set.",
			},
		},
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
	client, done, err := b.Client(req.Storage)
	if err != nil {
		return nil, err
	}

	defer done()

	psName := d.Get("permissionset").(string)

	ps, _ := getPermissionSet(ctx, psName, req.Storage)
	if ps == nil {
		return logical.ErrorResponse("permission set '%s' does not exist", psName), nil
	}

	opts := ps.TokenOptions

	// Instrument and log the token API call, recording status, duration and
	// whether any constraints (permissions, repositories, repository IDs) were
	// requested.
	defer func(begin time.Time) {
		duration := time.Since(begin)
		b.Logger().Debug("attempted to create a new installation token",
			"took", duration.String(),
			"err", err,
			"permissions", opts.Permissions,
			"repository_ids", fmt.Sprint(opts.RepositoryIDs),
			"repositories", fmt.Sprint(opts.Repositories),
		)
		requestDuration.With(prometheus.Labels{
			"success":  strconv.FormatBool(err == nil),
			keyPerms:   strconv.FormatBool(len(opts.Permissions) > 0),
			keyRepoIDs: strconv.FormatBool(len(opts.RepositoryIDs) > 0),
			keyRepos:   strconv.FormatBool(len(opts.Repositories) > 0),
		}).Observe(duration.Seconds())
	}(time.Now())

	// Perform the token request.
	return client.Token(ctx, opts)
}
