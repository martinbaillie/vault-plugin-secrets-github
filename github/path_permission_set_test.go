package github

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"
)

func testBackendPermissionSet(t *testing.T) {
	t.Helper()

	t.Run("ValidateNameEmpty", func(t *testing.T) {
		t.Parallel()

		_, storage := testBackend(t)

		ps := &PermissionSet{}
		err := ps.save(context.Background(), storage)
		assert.Assert(t, errors.Is(err, errPermissionSetNameEmpty))
	})
	t.Run("ValidateTokenOptionEmpty", func(t *testing.T) {
		t.Parallel()

		_, storage := testBackend(t)

		ps := &PermissionSet{Name: "foo"}
		err := ps.save(context.Background(), storage)
		assert.Assert(t, errors.Is(err, errPermissionSetTokenOptionEmpty))
	})
	t.Run("FailSave", func(t *testing.T) {
		t.Parallel()

		_, storage := testBackend(t, failVerbPut)

		ps := &PermissionSet{Name: "foo", TokenOptions: new(tokenOptions)}
		err := ps.save(context.Background(), storage)
		assert.Assert(t, err != nil)
	})
	t.Run("ValidateGetPermissionSet", func(t *testing.T) {
		t.Parallel()

		_, storage := testBackend(t, failVerbRead)
		_, err := getPermissionSet(context.Background(), "foo", storage)
		assert.Assert(t, err != nil)

	})
}

func testBackendPathPermissionSetWrite(t *testing.T, op logical.Operation) {
	t.Helper()

	t.Run("HappyPath", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		_, err := b.HandleRequest(context.Background(), &logical.Request{
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
	})
	t.Run("CreateFail", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbRead)

		_, err := b.HandleRequest(context.Background(), &logical.Request{
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
		assert.Assert(t, err != nil)
		b, storage = testBackend(t, failVerbPut)

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
	})
}

func testBackendPathPermissionSetDelete(t *testing.T, op logical.Operation) {
	t.Helper()

	t.Run("HappyPath", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      "permissionset/foo",
			Data: map[string]interface{}{
				keyInstallationID: testInsID1,
				keyRepos:          []string{testRepo1, testRepo2},
				keyRepoIDs:        []int{testRepoID1, testRepoID2},
				keyPerms:          testPerms,
			},
		})
		assert.NilError(t, err)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      "permissionset/foo",
			Data:      map[string]interface{}{},
		})
		assert.NilError(t, err)
	})

	t.Run("DeleteNonExistent", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      "permissionset/doensnt-exist",
			Data:      map[string]interface{}{},
		})
		assert.NilError(t, err)
	})
	t.Run("DeleteFail", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbRead)

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      "permissionset/foo",
			Data:      map[string]interface{}{},
		})
		assert.Assert(t, err != nil)

		b, storage = testBackend(t, failVerbDelete)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      "permissionset/foo",
			Data:      map[string]interface{}{},
		})
		assert.Assert(t, err != nil)
	})
}

func testBackendPathPermissionSetRead(t *testing.T, op logical.Operation) {
	t.Helper()

	t.Run("HappyPath", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
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
			Path:      "permissionset/foo",
			Data:      map[string]interface{}{},
		})
		assert.NilError(t, err)
		permData := r.Data[keyPerms].(map[string]string)
		installationIDData := r.Data[keyInstallationID].(int)
		repoIDData := r.Data[keyRepoIDs].([]int)
		repoData := r.Data[keyRepos].([]string)
		assert.DeepEqual(t, installationIDData, testInsID1)
		assert.DeepEqual(t, permData, testPerms)
		assert.DeepEqual(t, repoIDData, []int{testRepoID1, testRepoID2})
		assert.DeepEqual(t, repoData, []string{testRepo1, testRepo2})
	})

	t.Run("NonExistenceCheck", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      "permissionset/bar",
			Data:      map[string]interface{}{},
		})
		assert.NilError(t, err)
		assert.Assert(t, r == nil)
	})

	t.Run("ReadFail", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbRead)

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      "permissionset/bar",
			Data:      map[string]interface{}{},
		})
		assert.Assert(t, err != nil)
	})
}

func testBackendPathPermissionSetList(t *testing.T, op logical.Operation) {
	t.Helper()

	t.Run("HappyPath", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
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
			Path:      "permissionsets/",
			Data:      map[string]interface{}{},
		})
		assert.NilError(t, err)
		assert.Assert(t, r.Data != nil)
	})
	t.Run("ListFail", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbList)

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      "permissionset/foo",
			Data: map[string]interface{}{
				keyInstallationID: testInsID1,
				keyRepos:          []string{testRepo1, testRepo2},
				keyRepoIDs:        []int{testRepoID1, testRepoID2},
				keyPerms:          testPerms,
			},
		})
		assert.NilError(t, err)

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      "permissionsets/",
			Data:      map[string]interface{}{},
		})
		assert.Assert(t, err != nil)
	})
}
func TestBackend_PermissionSet(t *testing.T) {
	t.Parallel()
	testBackendPermissionSet(t)
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
