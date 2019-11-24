package github

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
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

// TODO(mbaillie): use a map or struct
var pathTokenHelpDesc = fmt.Sprintf(`
Create and return a token using the GitHub secrets plugin, optionally
constrained by the following properties:
%s:\t%s
%s:\t%s

NOTE: '%s' should be a comma separated list of repository IDs.
The quickest way to find a repository ID: https://stackoverflow.com/a/47223479

NOTE: '%s' is a map of permission names to their access type (read or write).
Permission names taken from: https://developer.github.com/v3/apps/permissions
`, keyRepoIDs, descRepoIDs, keyPerms, descPerms, keyRepoIDs, keyPerms)

func (b *backend) pathToken() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternToken,
		Fields: map[string]*framework.FieldSchema{
			keyRepoIDs: {
				Type:        framework.TypeCommaIntSlice,
				Description: descRepoIDs,
			},
			keyPerms: {
				Type:        framework.TypeMap,
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
) (*logical.Response, error) {
	client, done, err := b.Client(req.Storage)
	if err != nil {
		return nil, err
	}

	defer done()

	b.Logger().Debug("creating GitHub App installation token")

	return client.Token(ctx, d)
}
