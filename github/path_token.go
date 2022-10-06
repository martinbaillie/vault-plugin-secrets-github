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
	// NOTE: keys match official GitHub access tokens API[1] payload attribute
	// names for ease of marshalling.
	//
	// [1]: https://git.io/JsQ7n
	keyRepos           = "repositories"
	descRepos          = "The repository names that the token should have access to."
	keyRepoIDs         = "repository_ids"
	descRepoIDs        = "The IDs of the repositories that the token can access."
	keyOrgName         = "org_name" // NOTE: Not a real API attribute.
	descOrgName        = "The organization name with App installation."
	keyPerms           = "permissions"
	descPerms          = "The permissions granted to the token."
	keyInstallationID  = "installation_id"
	descInstallationID = "The ID of the App installation that the token should have access to."
)

//nolint:gosec // false positive.
const pathTokenHelpSyn = `
Create and return a token using the GitHub secrets plugin.
`

var pathTokenHelpDesc = fmt.Sprintf(`
Create and return a token using the GitHub secrets plugin.

NOTE: %q is an installation ID and %q is an organization name. You can
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

func (b *backend) pathToken() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternToken,
		Fields: map[string]*framework.FieldSchema{
			keyInstallationID: {
				Type:        framework.TypeInt,
				Description: descInstallationID,
			},
			keyOrgName: {
				Type:        framework.TypeString,
				Description: descOrgName,
			},
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
	client, done, err := b.Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	defer done()

	// Safely parse the request and any options from interface types.
	tokReq := &tokenRequest{
		InstallationID: d.Get(keyInstallationID).(int),
		OrgName:        d.Get(keyOrgName).(string),
	}

	if tokReq.InstallationID == 0 && tokReq.OrgName == "" {
		return logical.ErrorResponse(
			"%s or %s is a required parameter",
			keyInstallationID,
			keyOrgName,
		), nil
	}

	if perms, ok := d.GetOk(keyPerms); ok {
		tokReq.Permissions = perms.(map[string]string)
	}

	if repoIDs, ok := d.GetOk(keyRepoIDs); ok {
		tokReq.RepositoryIDs = repoIDs.([]int)
	}

	if repos, ok := d.GetOk(keyRepos); ok {
		tokReq.Repositories = repos.([]string)
	}

	// Instrument and log the token API call, recording status, duration and
	// whether any constraints (permissions, repository IDs) were requested.
	defer func(begin time.Time) {
		duration := time.Since(begin)
		b.Logger().Debug("attempted to create a new installation token",
			"took", duration.String(),
			"err", err,
			"permissions", tokReq.Permissions,
			"org_name", tokReq.OrgName,
			"installation_id", fmt.Sprint(tokReq.InstallationID),
			"repository_ids", fmt.Sprint(tokReq.RepositoryIDs),
			"repositories", fmt.Sprint(tokReq.Repositories),
		)
		requestDuration.With(prometheus.Labels{
			"success":         strconv.FormatBool(err == nil),
			keyOrgName:        tokReq.OrgName,
			keyInstallationID: fmt.Sprint(tokReq.InstallationID),
			keyPerms:          strconv.FormatBool(len(tokReq.Permissions) > 0),
			keyRepoIDs:        strconv.FormatBool(len(tokReq.RepositoryIDs) > 0),
			keyRepos:          strconv.FormatBool(len(tokReq.Repositories) > 0),
		}).Observe(duration.Seconds())
	}(time.Now())

	// Perform the token request.
	return client.Token(ctx, tokReq)
}
