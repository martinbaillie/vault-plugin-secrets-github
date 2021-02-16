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
	// is "gotest.tools/assert/cmp"
)

func testBackendPathPermissionSetWrite(t *testing.T, op logical.Operation) {
	t.Helper()

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
				keyInsID:   testInsID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      fmt.Sprintf("permissionset/foo"),
			Data: map[string]interface{}{
				keyRepoIDs: []int{testRepoID1, testRepoID2},
				keyPerms:   testPerms,
			},
		})
		assert.NilError(t, err)
	})
}

func testBackendPathPermissionSetDelete(t *testing.T, op logical.Operation) {
	t.Helper()

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
				keyInsID:   testInsID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      fmt.Sprintf("permissionset/foo"),
			Data: map[string]interface{}{
				keyRepoIDs: []int{testRepoID1, testRepoID2},
				keyPerms:   testPerms,
			},
		})
		assert.NilError(t, err)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      fmt.Sprintf("permissionset/foo"),
			Data:      map[string]interface{}{},
		})
		assert.NilError(t, err)
	})

}

func testBackendPathPermissionSetRead(t *testing.T, op logical.Operation) {
	t.Helper()

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
				keyInsID:   testInsID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      fmt.Sprintf("permissionset/foo"),
			Data: map[string]interface{}{
				keyRepoIDs: []int{testRepoID1, testRepoID2},
				keyPerms:   testPerms,
			},
		})
		assert.NilError(t, err)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      fmt.Sprintf("permissionset/foo"),
			Data:      map[string]interface{}{},
		})
		assert.NilError(t, err)
		permData := r.Data[keyPerms].(map[string]string)
		repoData := r.Data[keyRepoIDs].([]int)
		assert.DeepEqual(t, permData, testPerms)
		assert.DeepEqual(t, repoData, []int{testRepoID1, testRepoID2})
	})
}

func testBackendPathPermissionSetList(t *testing.T, op logical.Operation) {
	t.Helper()

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
				keyInsID:   testInsID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      fmt.Sprintf("permissionset/foo"),
			Data: map[string]interface{}{
				keyRepoIDs: []int{testRepoID1, testRepoID2},
				keyPerms:   testPerms,
			},
		})
		assert.NilError(t, err)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      fmt.Sprintf("permissionsets/"),
			Data:      map[string]interface{}{},
		})
		assert.NilError(t, err)
		assert.Assert(t, r.Data != nil)
	})
}
func TestBackend_PathPermissionSetRead(t *testing.T) {
	t.Parallel()
	testBackendPathPermissionSetRead(t, logical.ReadOperation)
}

func TestBackend_PathPermissionSetDelete(t *testing.T) {
	t.Parallel()
	testBackendPathPermissionSetDelete(t, logical.DeleteOperation)
}

func TestBackend_PathPermissionSetWriteCreate(t *testing.T) {
	t.Parallel()
	testBackendPathPermissionSetWrite(t, logical.CreateOperation)
}

func TestBackend_PathPermissionSetWriteUpdate(t *testing.T) {
	t.Parallel()
	testBackendPathPermissionSetWrite(t, logical.UpdateOperation)
}

func TestBackend_PathPermissionSetList(t *testing.T) {
	t.Parallel()
	testBackendPathPermissionSetList(t, logical.ListOperation)
}
