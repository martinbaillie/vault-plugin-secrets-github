package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"

	is "gotest.tools/assert/cmp"
)

func testBackendPathTokenPermissionSetWrite(t *testing.T, op logical.Operation) {
	t.Helper()

	t.Run("FailedValidation", func(t *testing.T) {
		t.Parallel()
		testFieldValidation(t, op, pathPatternConfig)
	})

	t.Run("HappyPath", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		ts := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				body, _ := json.Marshal(map[string]interface{}{
					"token":      testToken,
					"expires_at": testTokenExp,
				})
				w.WriteHeader(http.StatusCreated)
				w.Write(body)
			}),
		)
		defer ts.Close()

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      pathPatternConfig,
			Data: map[string]interface{}{
				keyAppID:   testAppID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      "permissionset/foo",
			Data: map[string]interface{}{
				keyInstallationID: testInsID1,
				keyRepos:          []string{testRepo1, testRepo2},
				keyRepoIDs:        []int{testRepoID1, testRepoID2},
				keyPerms:          testPerms,
			},
		})
		assert.NilError(t, err)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      fmt.Sprintf("%s/foo", pathPatternToken),
			Data:      map[string]interface{}{},
		})
		assert.NilError(t, err)

		assert.Assert(t, r != nil)
		assert.Equal(t, r.Data["expires_at"].(string), testTokenExp)
		assert.Equal(t, r.Data["token"].(string), testToken)
	})

	t.Run("FailedClient", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbRead)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      fmt.Sprintf("%s/foo", pathPatternToken),
		})
		assert.Assert(t, is.Nil(r))
		assert.ErrorContains(t, err, fmtErrConfRetrieval)
	})

	t.Run("FailedCreate", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		ts := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				t.Helper()
				w.WriteHeader(http.StatusUnprocessableEntity)
			}),
		)
		defer ts.Close()

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      pathPatternConfig,
			Data: map[string]interface{}{
				keyAppID:   testAppID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      fmt.Sprintf("%s/foo", pathPatternToken),
		})
		assert.Assert(t, err == nil)
	})
}

func TestBackend_PathTokenPermissionSetWriteCreate(t *testing.T) {
	t.Parallel()
	testBackendPathTokenPermissionSetWrite(t, logical.CreateOperation)
}

func TestBackend_PathTokenPermissionSetWriteUpdate(t *testing.T) {
	t.Parallel()
	testBackendPathTokenPermissionSetWrite(t, logical.UpdateOperation)
}
