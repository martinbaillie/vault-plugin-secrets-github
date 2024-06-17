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

// pathPatternInstallation is the string used to define the base path of the installation
// endpoint.
const pathPatternInstallations = "installations"

//nolint:gosec // false positive.
const pathInstallationsHelpSyn = `
List App Installations using the GitHub secrets plugin.
`

var pathInstallationsHelpDesc = fmt.Sprintf(`
Return Installations of the GitHub App using the GitHub secrets plugin.
`)

func (b *backend) pathInstallations() *framework.Path {
	return &framework.Path{
		Pattern:        pathPatternInstallations,
		Fields:         map[string]*framework.FieldSchema{},
		ExistenceCheck: b.pathInstallationsExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			// As per the issue request in https://git.io/JUhRk, allow Vault
			// Reads (i.e. HTTP GET) to also write the GitHub Installationss.
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathInstallationsWrite),
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathInstallationsWrite),
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathInstallationsWrite),
			},
		},
		HelpSynopsis:    pathInstallationsHelpSyn,
		HelpDescription: pathInstallationsHelpDesc,
	}
}

// pathInstallationsWrite corresponds to READ, CREATE and UPDATE on /github/Installations.
func (b *backend) pathInstallationsWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (res *logical.Response, err error) {
	client, done, err := b.Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	defer done()

	// Instrument and log the Installations API call, recording status, duration and
	// whether any constraints (permissions, repository IDs) were requested.
	defer func(begin time.Time) {
		duration := time.Since(begin)
		b.Logger().Debug("attempted to fetch installations",
			"took", duration.String(),
			"err", err,
		)
		requestDuration.With(prometheus.Labels{
			"success": strconv.FormatBool(err == nil),
		}).Observe(duration.Seconds())
	}(time.Now())

	// Perform the Installations request.
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
