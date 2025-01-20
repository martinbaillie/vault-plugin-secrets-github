package github

import (
	"context"
	"strconv"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/prometheus/client_golang/prometheus"
)

// pathPatternInstallation is the string used to define the base path of the
// installations endpoint.
const pathPatternInstallations = "installations"

const (
	pathInstallationsHelpSyn = `
List GitHub App installations associated with this plugin's configuration.
`
	pathInstallationsHelpDesc = `
This endpoint returns a mapping of GitHub organization names to their
corresponding installation IDs for the App associated with this plugin's
configuration. It automatically handles GitHub API pagination, combining results
from all pages into a single response. This ensures complete results even for
GitHub Apps installed on many organizations.
`
)

func (b *backend) pathInstallations() *framework.Path {
	return &framework.Path{
		Pattern:        pathPatternInstallations,
		Fields:         map[string]*framework.FieldSchema{},
		ExistenceCheck: b.pathInstallationsExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			// As per the issue request in https://git.io/JUhRk, allow Vault
			// Reads (i.e. HTTP GET) to also write the GitHub installations.
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathInstallationsWrite),
			},
		},
		HelpSynopsis:    pathInstallationsHelpSyn,
		HelpDescription: pathInstallationsHelpDesc,
	}
}

// pathInstallationsWrite corresponds to READ, CREATE and UPDATE on /github/installations.
func (b *backend) pathInstallationsWrite(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (res *logical.Response, err error) {
	client, done, err := b.Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	defer done()

	// Instrument and log the installations API call, recording status, duration and
	// whether any constraints (permissions, repository IDs) were requested.
	defer func(begin time.Time) {
		duration := time.Since(begin)
		b.Logger().Debug("attempted to fetch installations",
			"took", duration.String(),
			"err", err,
		)
		installationsDuration.With(prometheus.Labels{
			"success": strconv.FormatBool(err == nil),
		}).Observe(duration.Seconds())
	}(time.Now())

	// Perform the installations request.
	return client.ListInstallations(ctx)
}

// pathInstallationsExistenceCheck always returns false to force the Create path. This
// plugin predates the framework's 'ExistenceCheck' features and we wish to
// avoid changing any contracts with the user at this stage. Installations are created
// regardless of whether the request is a CREATE, UPDATE or even READ (per a
// user's request (https://git.io/JUhRk).
func (b *backend) pathInstallationsExistenceCheck(
	context.Context, *logical.Request, *framework.FieldData,
) (bool, error) {
	return false, nil
}
