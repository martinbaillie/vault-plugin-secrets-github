package github

import (
	"context"
	"encoding/json"
	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testBackendPathInstallations(t *testing.T, op logical.Operation) {
	t.Helper()

	t.Run("HappyPath", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		ts := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()

				body, _ := json.Marshal(map[string]any{
					"installations": []map[string]any{
						{"id": 1, "account": map[string]any{"login": "test"}},
					},
				})
				w.WriteHeader(http.StatusOK)
				w.Write(body)
			}),
		)
		defer ts.Close()

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      pathPatternConfig,
			Data: map[string]any{
				keyAppID:   testAppID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      pathPatternInstallations,
		})
		assert.NilError(t, err)

		assert.Assert(t, r != nil)
		assert.Assert(t, len(r.Data["installations"].([]map[string]any)) > 0)
	})

	t.Run("FailedClient", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbRead)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      pathPatternInstallations,
		})
		assert.ErrorContains(t, err, errConfRetrieval.Error())
		assert.Assert(t, r == nil)
	})

	t.Run("FailedInstallationsRequest", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		ts := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()
				w.WriteHeader(http.StatusInternalServerError)
			}),
		)
		defer ts.Close()

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      pathPatternConfig,
			Data: map[string]any{
				keyAppID:   testAppID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      pathPatternInstallations,
		})
		assert.ErrorContains(t, err, "500 Internal Server Error")
		assert.Assert(t, r == nil)
	})
}

func TestBackend_PathInstallationsRead(t *testing.T) {
	t.Parallel()
	testBackendPathInstallations(t, logical.ReadOperation)
}
