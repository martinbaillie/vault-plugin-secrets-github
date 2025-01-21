package github

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/common/expfmt"
)

const prefixMetrics = "vault_github_token"

const (
	errNoMetricsToDecode     = Error("no prometheus metrics could be decoded")
	errFailedMetricsEncoding = Error("failed to encode metrics")
)

const pathPatternMetrics = "metrics"

const pathMetricsHelpSyn = `
Display GitHub secrets plugin metrics in a Prometheus exposition format.
`

var pathMetricsHelpDesc = fmt.Sprintf(`
Display GitHub secrets plugin metrics in a Prometheus exposition format.

In addition to standard Go metrics, the following custom metrics are exposed:
- %s_request_duration_seconds: a summary of token request latency and status
- %s_build_info: a constant with useful build information
`, prefixMetrics, prefixMetrics)

// requestDuration records useful metric data about backend token requests.
var requestDuration = prometheus.NewSummaryVec(prometheus.SummaryOpts{
	Name:       fmt.Sprintf("%s_request_duration_seconds", prefixMetrics),
	Help:       "Total duration of Vault GitHub token requests in seconds.",
	Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
}, []string{"success", keyInstallationID, keyOrgName, keyPerms, keyRepoIDs, keyRepos})

// installationsDuration records useful metric data about installation requests.
var installationsDuration = prometheus.NewSummaryVec(prometheus.SummaryOpts{
	Name:       fmt.Sprintf("%s_installations_duration_seconds", prefixMetrics),
	Help:       "Total duration of Vault GitHub installation requests in seconds.",
	Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
}, []string{"success"})

// revokeDuration records useful metric data about backend token revocations.
var revokeDuration = prometheus.NewSummaryVec(prometheus.SummaryOpts{
	Name:       fmt.Sprintf("%s_revocation_request_duration_seconds", prefixMetrics),
	Help:       "Total duration of Vault GitHub token revocation requests in seconds.",
	Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
}, []string{"success"})

func init() {
	// Register standard and custom metric collectors globally.
	prometheus.MustRegister(
		version.NewCollector(prefixMetrics),
		collectors.NewBuildInfoCollector(),
		requestDuration,
		revokeDuration,
	)
}

func (b *backend) pathMetrics() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternMetrics,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathMetricsRead,
			},
		},
		HelpSynopsis:    pathMetricsHelpSyn,
		HelpDescription: pathMetricsHelpDesc,
	}
}

func (b *backend) pathMetricsRead(
	_ context.Context,
	_ *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	res := &logical.Response{
		// Default as failure.
		Data: map[string]any{
			logical.HTTPContentType: "text/plain",
			logical.HTTPStatusCode:  http.StatusBadRequest,
		},
	}

	// Gather metrics.
	metricsFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil || len(metricsFamilies) == 0 {
		res.Data[logical.HTTPRawBody] = fmt.Sprintf("%s: %s", errNoMetricsToDecode, err)

		return res, fmt.Errorf("%s: %w", errNoMetricsToDecode, err)
	}

	buf := new(bytes.Buffer)
	defer buf.Reset()

	text := expfmt.NewFormat(expfmt.TypeTextPlain)
	// Write metrics as Prometheus exposition format.
	for _, mf := range metricsFamilies {
		if err = expfmt.NewEncoder(buf, text).Encode(mf); err != nil {
			res.Data[logical.HTTPRawBody] = fmt.Sprintf("%s: %s", errFailedMetricsEncoding, err)

			return res, fmt.Errorf("%s: %w", errFailedMetricsEncoding, err)
		}
	}

	res.Data[logical.HTTPStatusCode] = http.StatusOK
	res.Data[logical.HTTPContentType] = string(text)
	res.Data[logical.HTTPRawBody] = buf.Bytes()

	return res, nil
}
