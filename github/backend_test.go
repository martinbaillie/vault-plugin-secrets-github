package github

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"

	"github.com/hashicorp/go-hclog"
	is "gotest.tools/assert/cmp"
)

func TestFactory(t *testing.T) {
	t.Parallel()

	var cases = []struct {
		name string
		conf *logical.BackendConfig
		err  error
	}{
		{
			name: "HappyPath",
			conf: &logical.BackendConfig{},
		},
		{
			name: "NilConfig",
			err:  errBackendConfigNil,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			backend, err := Factory(context.Background(), tc.conf)

			if tc.err != nil {
				assert.Assert(t, is.Nil(backend))
				assert.Error(t, err, tc.err.Error())
			} else {
				assert.Assert(t, is.Nil(err))
			}
		})
	}
}

type failVerb int

const (
	failVerbRead failVerb = iota
	failVerbPut
	failVerbList
	failVerbDelete
)

// testBackend creates a new isolated instance of the backend for testing.
// failVerbs can be used to have the underlying storage report failures.
func testBackend(t *testing.T, fvs ...failVerb) (*backend, logical.Storage) {
	t.Helper()

	storageView := new(logical.InmemStorage)
	for _, fv := range fvs {
		switch fv {
		case failVerbRead:
			storageView.Underlying().FailGet(true)
		case failVerbPut:
			storageView.Underlying().FailPut(true)
		case failVerbList:
			storageView.Underlying().FailList(true)
		case failVerbDelete:
			storageView.Underlying().FailDelete(true)
		}
	}

	config := logical.TestBackendConfig()
	config.StorageView = storageView
	config.Logger = hclog.NewNullLogger()

	b, err := Factory(context.Background(), config)
	assert.NilError(t, err)

	return b.(*backend), config.StorageView
}

func TestBackend_Config(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		new         []byte
		exp         *Config
		failStorage []failVerb
		err         error
	}{
		{
			name: "Empty",
			exp:  NewConfig(),
		},
		{
			name: "HappyPath",
			new: []byte(fmt.Sprintf(`{"%s":%d, "%s":%d}`,
				keyAppID, testAppID1, keyInsID, testInsID1)),
			exp: &Config{
				AppID:   testAppID1,
				InsID:   testInsID1,
				BaseURL: githubPublicAPI,
			},
		},
		{
			name: "Organization",
			new: []byte(fmt.Sprintf(`{"%s":%d, "%s":"%s"}`,
				keyAppID, testAppID1, keyOrgName, testOrgName1)),
			exp: &Config{
				AppID:   testAppID1,
				OrgName: testOrgName1,
				BaseURL: githubPublicAPI,
			},
		},
		{
			name:        "FailedStorage",
			failStorage: []failVerb{failVerbRead, failVerbPut, failVerbList, failVerbDelete},
			err:         errors.New(fmtErrConfRetrieval),
		},
		{
			name: "FailedUnmarshal",
			new:  []byte(`{bustedJSON`),
			err:  errors.New(fmtErrConfUnmarshal),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b, storage := testBackend(t, tc.failStorage...)

			if tc.new != nil {
				assert.NilError(t, storage.Put(context.Background(), &logical.StorageEntry{
					Key:   pathPatternConfig,
					Value: tc.new,
				}))
			}

			c, err := b.Config(context.Background(), storage)
			if tc.err != nil {
				assert.ErrorContains(t, err, tc.err.Error())
			} else {
				assert.NilError(t, err)
			}

			assert.DeepEqual(t, c, tc.exp)
		})
	}
}

func TestBackend_Client(t *testing.T) {
	t.Parallel()

	t.Run("AllowConcurrentReads", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		entry, err := logical.StorageEntryJSON(pathPatternConfig, &Config{
			AppID:   testAppID1,
			InsID:   testInsID1,
			PrvKey:  testPrvKeyValid,
			BaseURL: testBaseURLValid,
		})
		assert.NilError(t, err)
		assert.Assert(t, entry != nil)
		assert.NilError(t, storage.Put(context.Background(), entry))

		_, closer1, err := b.Client(storage)
		assert.NilError(t, err)
		defer closer1()

		doneCh := make(chan struct{})
		go func() {
			_, closer2, err := b.Client(storage)
			assert.NilError(t, err)
			defer closer2()
			close(doneCh)
		}()

		select {
		case <-doneCh:
		case <-time.After(1 * time.Second):
			t.Errorf("client was not available")
		}
	})

	t.Run("ReusesExisting", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		entry, err := logical.StorageEntryJSON(pathPatternConfig, &Config{
			AppID:   testAppID1,
			InsID:   testInsID1,
			PrvKey:  testPrvKeyValid,
			BaseURL: testBaseURLValid,
		})
		assert.NilError(t, err)
		assert.Assert(t, entry != nil)
		assert.NilError(t, storage.Put(context.Background(), entry))

		client1, closer1, err := b.Client(storage)
		assert.NilError(t, err)
		defer closer1()

		client2, closer2, err := b.Client(storage)
		assert.NilError(t, err)
		defer closer2()

		// NOTE: actually checking equality here.
		assert.Equal(t, client1, client2)
	})

	t.Run("FailedStorage", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbRead)

		client, _, err := b.Client(storage)
		assert.ErrorContains(t, err, fmtErrConfRetrieval)
		assert.Assert(t, is.Nil(client))
	})

	t.Run("BadConfig", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		entry, err := logical.StorageEntryJSON(pathPatternConfig, &Config{
			PrvKey: "not a private key",
		})
		assert.NilError(t, err)
		assert.Assert(t, entry != nil)
		assert.NilError(t, storage.Put(context.Background(), entry))

		client, _, err := b.Client(storage)
		assert.ErrorContains(t, err, fmtErrClientCreate)
		assert.Assert(t, is.Nil(client))
	})
}
