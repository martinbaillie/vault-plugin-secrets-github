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
const pathPatternToken = "token"

const (
	// NOTE: keys match GitHub installation permissions for ease of marshalling.
	// https://godoc.org/github.com/google/go-github/github#InstallationPermissions
	keyRepoIDs  = "repository_ids"
	descRepoIDs = "The IDs of the repositories that the token can access."
	keyPerms    = "permissions"
	descPerms   = "The permissions granted to the token."
)

const pathTokenHelpSyn = `
Create and return a token using the GitHub secrets plugin.
`

var pathTokenHelpDesc = fmt.Sprintf(`
Create and return a token using the GitHub secrets plugin, optionally
constrained by the above parameters.

NOTE: '%s' is a slice of repository IDs.
The quickest way to find a repository ID: https://stackoverflow.com/a/47223479

NOTE: '%s' is a map of permission names to their access type (read or write).
Permission names taken from: https://developer.github.com/v3/apps/permissions
`, keyRepoIDs, keyPerms)

func (b *backend) pathToken() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternToken,
		Fields: map[string]*framework.FieldSchema{
			keyRepoIDs: {
				Type:        framework.TypeCommaIntSlice,
				Description: descRepoIDs,
			},
			keyPerms: {
				Type:        framework.TypeKVPairs,
				Description: descPerms,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: withFieldValidator(b.pathTokenWrite),
			logical.UpdateOperation: withFieldValidator(b.pathTokenWrite),
		},
		HelpSynopsis:    pathTokenHelpSyn,
		HelpDescription: pathTokenHelpDesc,
	}
}

// pathTokenWrite corresponds to both CREATE and UPDATE on /github/token.
func (b *backend) pathTokenWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (res *logical.Response, err error) {
	client, done, err := b.Client(req.Storage)
	if err != nil {
		return nil, err
	}

	defer done()

	// Safely parse any options from interface types.
	var opts = new(tokenOptions)

	if perms, ok := d.GetOk(keyPerms); ok {
		opts.Permissions = perms.(map[string]string)
	}

	if repoIDs, ok := d.GetOk(keyRepoIDs); ok {
		opts.RepositoryIDs = repoIDs.([]int)
	}

	// Instrument and log the token API call, recording status, duration and
	// whether any constraints (permissions, repository IDs) were requested.
	defer func(begin time.Time) {
		duration := time.Since(begin)
		b.Logger().Debug("attempted to create a new installation token",
			"took", duration.String(),
			"err", err,
			"permissions", opts.Permissions,
			"repository_ids", fmt.Sprint(opts.RepositoryIDs),
		)
		requestDuration.With(prometheus.Labels{
			"success":  strconv.FormatBool(err == nil),
			keyPerms:   strconv.FormatBool(len(opts.Permissions) > 0),
			keyRepoIDs: strconv.FormatBool(len(opts.RepositoryIDs) > 0),
		}).Observe(duration.Seconds())
	}(time.Now())

	// Perform the token request.
	return client.Token(ctx, opts)
}
