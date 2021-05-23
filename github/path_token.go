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
	// SEE: https://git.io/JsQ7n
	keyRepos    = "repositories"
	descRepos   = "The repository names that the token should have access to"
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

NOTE: '%s' is a slice of repository names.
These must be the short names of repositories under the organisation.

NOTE: '%s' is a slice of repository IDs.
The quickest way to find a repository ID: https://stackoverflow.com/a/47223479

NOTE: '%s' is a map of permission names to their access type (read or write).
Permission names taken from: https://developer.github.com/v3/apps/permissions
`, keyRepos, keyRepoIDs, keyPerms)

func (b *backend) pathToken() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternToken,
		Fields: map[string]*framework.FieldSchema{
			keyRepos: {
				Type:        framework.TypeCommaStringSlice,
				Description: descRepos,
			},
			keyRepoIDs: {
				Type:        framework.TypeCommaIntSlice,
				Description: descRepoIDs,
			},
			keyPerms: {
				Type:        framework.TypeKVPairs,
				Description: descPerms,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			// As per the issue request in https://git.io/JUhRk, allow Vault
			// Reads (i.e. HTTP GET) to also write the GitHub tokens.
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathTokenWrite),
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathTokenWrite),
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathTokenWrite),
			},
		},
		HelpSynopsis:    pathTokenHelpSyn,
		HelpDescription: pathTokenHelpDesc,
	}
}

// pathTokenWrite corresponds to READ, CREATE and UPDATE on /github/token.
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
	opts := new(tokenOptions)

	if perms, ok := d.GetOk(keyPerms); ok {
		opts.Permissions = perms.(map[string]string)
	}

	if repoIDs, ok := d.GetOk(keyRepoIDs); ok {
		opts.RepositoryIDs = repoIDs.([]int)
	}

	if repos, ok := d.GetOk(keyRepos); ok {
		opts.Repositories = repos.([]string)
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
