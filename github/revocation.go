package github

import (
	"context"
	"strconv"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/prometheus/client_golang/prometheus"
)

// Revoke will handle Vault lease revocations for GitHub tokens by sending a
// token revocation request upstream to the configured GitHub.
func (b *backend) Revoke(
	ctx context.Context, req *logical.Request, d *framework.FieldData,
) (resp *logical.Response, retErr error) {
	client, done, err := b.Client(req.Storage)
	if err != nil {
		return nil, err
	}

	defer done()

	// Safely parse the token from interface type.
	var token string
	{
		var tokenIface any
		if tokenIface, _, err = d.GetOkErr("token"); err != nil {
			return nil, err
		}

		token = tokenIface.(string)
	}

	// Instrument and log the token API call, recording status and duration.
	defer func(begin time.Time) {
		duration := time.Since(begin)
		b.Logger().Debug("attempted to revoke an installation token",
			"took", duration.String(),
			"err", err,
		)
		revokeDuration.With(prometheus.Labels{
			"success": strconv.FormatBool(err == nil),
		}).Observe(duration.Seconds())
	}(time.Now())

	return client.RevokeToken(ctx, token)
}
