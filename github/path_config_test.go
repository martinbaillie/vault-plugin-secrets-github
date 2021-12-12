package github

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"

	is "gotest.tools/assert/cmp"
)

func TestBackend_PathConfigRead(t *testing.T) {
	t.Parallel()

	t.Run("FieldValidation", func(t *testing.T) {
		t.Parallel()
		testFieldValidation(t, logical.ReadOperation, pathPatternConfig)
	})

	t.Run("Empty", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      pathPatternConfig,
		})
		assert.NilError(t, err)
		assert.Assert(t, is.Contains(resp.Data, keyAppID))
		assert.Assert(t, is.Contains(resp.Data, keyInsID))
		assert.Assert(t, is.Contains(resp.Data, keyBaseURL))
	})

	t.Run("HappyPath", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		entry, err := logical.StorageEntryJSON(pathPatternConfig, &Config{
			AppID:   testAppID1,
			InsID:   testInsID1,
			PrvKey:  testPrvKeyValid,
			BaseURL: testBaseURLValid,
		})
		assert.NilError(t, err)
		assert.NilError(t, storage.Put(context.Background(), entry))

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      pathPatternConfig,
		})
		assert.NilError(t, err)

		assert.Assert(t, is.Contains(resp.Data, keyAppID))
		assert.Equal(t, testAppID1, resp.Data[keyAppID])
		assert.Assert(t, is.Contains(resp.Data, keyInsID))
		assert.Equal(t, testInsID1, resp.Data[keyInsID])
		assert.Assert(t, is.Contains(resp.Data, keyBaseURL))
		assert.DeepEqual(t, testBaseURLValid, resp.Data[keyBaseURL])
	})

	t.Run("FailedStorage", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbRead)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      pathPatternConfig,
		})
		assert.ErrorContains(t, err, fmtErrConfRetrieval)
		assert.Assert(t, is.Nil(resp))
	})
}

func testBackendPathConfigCreateUpdate(t *testing.T, op logical.Operation) {
	t.Helper()

	t.Run("FailedValidation", func(t *testing.T) {
		t.Parallel()
		testFieldValidation(t, op, pathPatternConfig)
	})

	t.Run("Empty", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      pathPatternConfig,
			Data: map[string]interface{}{
				keyAppID:   testAppID1,
				keyInsID:   testInsID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: testBaseURLValid,
			},
		})
		assert.NilError(t, err)

		config, err := b.Config(context.Background(), storage)
		assert.NilError(t, err)
		assert.Assert(t, config != nil)
		assert.Equal(t, testAppID1, config.AppID)
		assert.Equal(t, testInsID1, config.InsID)
		assert.DeepEqual(t, testBaseURLValid, config.BaseURL)
	})

	tcConfig := map[string]map[string]interface{}{
		"Installation": {
			keyAppID:   testAppID2,
			keyInsID:   testInsID2,
			keyPrvKey:  testPrvKeyValid,
			keyBaseURL: testBaseURLValid,
		},
		"Organization": {
			keyAppID:   testAppID2,
			keyOrgName: testOrgName2,
			keyPrvKey:  testPrvKeyValid,
			keyBaseURL: testBaseURLValid,
		},
	}

	for name, v := range tcConfig {
		t.Run("Exist"+name, func(t *testing.T) {
			t.Parallel()

			b, storage := testBackend(t)

			entry, err := logical.StorageEntryJSON(pathPatternConfig, &Config{
				AppID:   testAppID1,
				InsID:   testInsID1,
				OrgName: testOrgName1,
			})
			assert.NilError(t, err)
			assert.Assert(t, entry != nil)

			assert.NilError(t, storage.Put(context.Background(), entry))

			_, err = b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: op,
				Path:      pathPatternConfig,
				Data:      v,
			})
			assert.NilError(t, err)

			config, err := b.Config(context.Background(), storage)
			assert.NilError(t, err)
			assert.Assert(t, config != nil)
			assert.Equal(t, testAppID2, config.AppID)
			if name == "Installation" {
				assert.Equal(t, testInsID2, config.InsID)
			} else {
				assert.Equal(t, testOrgName2, config.OrgName)
			}

			assert.DeepEqual(t, testBaseURLValid, config.BaseURL)
		})
	}

	t.Run("FailedStorageRetrieve", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbRead)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      pathPatternConfig,
		})
		assert.ErrorContains(t, err, fmtErrConfRetrieval)
		assert.Assert(t, is.Nil(resp))
	})

	for name, v := range tcConfig {
		t.Run("FailedStoragePersist"+name, func(t *testing.T) {
			t.Parallel()

			b, storage := testBackend(t, failVerbPut)

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: op,
				Path:      pathPatternConfig,
				Data:      v,
			})
			assert.ErrorContains(t, err, fmtErrConfPersist)
			assert.Assert(t, is.Nil(resp))
		})
	}

	t.Run("FailedValidation", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      pathPatternConfig,
			Data: map[string]interface{}{
				keyPrvKey: "not a private key",
			},
		})
		assert.Error(t, err, errKeyNotPEMFormat.Error())
		assert.Assert(t, is.Nil(resp))
	})
}

func TestBackend_PathConfigCreate(t *testing.T) {
	t.Parallel()
	testBackendPathConfigCreateUpdate(t, logical.CreateOperation)
}

func TestBackend_PathConfigUpdate(t *testing.T) {
	t.Parallel()
	testBackendPathConfigCreateUpdate(t, logical.UpdateOperation)
}

func TestBackend_PathConfigDelete(t *testing.T) {
	t.Parallel()

	t.Run("FieldValidation", func(t *testing.T) {
		t.Parallel()
		testFieldValidation(t, logical.DeleteOperation, pathPatternConfig)
	})

	t.Run("Empty", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.DeleteOperation,
			Path:      pathPatternConfig,
		})
		assert.NilError(t, err)
		assert.Assert(t, is.Nil(resp))

		config, err := b.Config(context.Background(), storage)
		assert.NilError(t, err)
		assert.DeepEqual(t, config, NewConfig())
	})

	t.Run("HappyPath", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		entry, err := logical.StorageEntryJSON(pathPatternConfig, &Config{
			AppID:   testAppID1,
			InsID:   testInsID1,
			PrvKey:  testPrvKeyValid,
			BaseURL: testBaseURLValid,
		})
		assert.NilError(t, err)
		assert.NilError(t, storage.Put(context.Background(), entry))

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.DeleteOperation,
			Path:      pathPatternConfig,
		})
		assert.NilError(t, err)
		assert.Assert(t, is.Nil(resp))

		config, err := b.Config(context.Background(), storage)
		assert.NilError(t, err)
		assert.DeepEqual(t, config, NewConfig())
	})

	t.Run("FailedStorage", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbDelete)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.DeleteOperation,
			Path:      pathPatternConfig,
		})
		assert.ErrorContains(t, err, fmtErrConfDelete)
		assert.Assert(t, is.Nil(resp))
	})
}
