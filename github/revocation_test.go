package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestBackend_Revoke(t *testing.T) {
	t.Parallel()

	t.Run("HappyPath", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		ts := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				w.WriteHeader(http.StatusNoContent)
			}),
		)
		defer ts.Close()

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      pathPatternConfig,
			Data: map[string]interface{}{
				keyAppID:   testAppID1,
				keyInsID:   testInsID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.RevokeOperation,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{"secret_type": backendSecretType},
			},
			Data: map[string]interface{}{
				"token": testToken,
			},
		})
		assert.NilError(t, err)
		assert.DeepEqual(t, r, &logical.Response{})
	})

	t.Run("FailedClient", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbRead)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.RevokeOperation,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{"secret_type": backendSecretType},
			},
		})
		assert.Assert(t, is.Nil(r))
		assert.ErrorContains(t, err, fmtErrConfRetrieval)
	})

	t.Run("FailedOptionsParsing", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbRead)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.RevokeOperation,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{"secret_type": backendSecretType},
			},
			Data: map[string]interface{}{
				"token": struct{}{},
			},
		})
		assert.Assert(t, is.Nil(r))
		assert.Assert(t, err != nil)
	})

	t.Run("FailedRevoke", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		ts := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				w.WriteHeader(http.StatusUnauthorized)
			}),
		)
		defer ts.Close()

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      pathPatternConfig,
			Data: map[string]interface{}{
				keyAppID:   testAppID1,
				keyInsID:   testInsID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.RevokeOperation,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{"secret_type": backendSecretType},
			},
			Data: map[string]interface{}{
				"token": testToken,
			},
		})
		assert.Assert(t, is.Nil(r))
		fmt.Println(err)
		assert.Assert(t, errors.Is(err, errUnableToRevokeAccessToken))
	})
}
