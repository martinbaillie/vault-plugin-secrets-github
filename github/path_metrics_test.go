package github

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"gotest.tools/assert"
)

func TestBackend_PathMetricsRead(t *testing.T) {
	t.Parallel()

	t.Run("HappyPath", func(t *testing.T) {
		b, storage := testBackend(t)

		res, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      pathPatternMetrics,
		})

		assert.NilError(t, err)
		assert.Assert(t, statusCode(res.Data[logical.HTTPStatusCode].(int)).Successful())
		assert.Equal(t, res.Data[logical.HTTPContentType], string(expfmt.NewFormat(expfmt.TypeTextPlain)))
		assert.Assert(t, strings.Contains(
			string(res.Data[logical.HTTPRawBody].([]byte)),
			fmt.Sprintf("%s_build_info", prefixMetrics)),
		)
	})

	t.Run("NoMetrics", func(t *testing.T) {
		b, storage := testBackend(t)

		// Empty the metric registry.
		oldRegistry := prometheus.DefaultGatherer
		defer func() { prometheus.DefaultGatherer = oldRegistry }()
		prometheus.DefaultGatherer = prometheus.NewRegistry()

		res, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      pathPatternMetrics,
		})
		assert.ErrorContains(t, err, errNoMetricsToDecode.Error())
		assert.Assert(t, statusCode(res.Data[logical.HTTPStatusCode].(int)).Unsuccessful())
		assert.Assert(t, strings.Contains(
			res.Data[logical.HTTPRawBody].(string),
			errNoMetricsToDecode.Error()),
		)
	})
}
