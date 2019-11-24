package github

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"

	hclog "github.com/hashicorp/go-hclog"
	is "gotest.tools/assert/cmp"
)

const (
	_martinVaultAppID        = "45792"
	_martinVaultInstID       = "5018413"
	_martinVaultClientID     = "Iv1.18ee8be3a4d623c2"
	_martinVaultClientSecret = "30ca9eb3e81bdfeeafbc4962ae7aba5ab10484e0"
	_martinVaultPrvKey       = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvPdtXHe2CjNgCZbjpPGT9tkOloOvEfrqQhW5uGq2vRepdMWE
rrV0CtcIk6kYRPfW9D8+XZfI7YBnW2uy/CqTUVWqVfnz70uOzurmOAeYOVzwQtHB
e4GXrdVZR2pKD1De2hO5o1QL09Er99EMxaD9mPFsWqj0ybrYYRPeT0b0kgmdwgu7
QRJjUW6Ynbb6GCYI3VcRkxaEE3Hd9BQhDyLpXAnyStM1h5hnxDsx5hGnbadWyII0
ztLQjFlNDkv/5gvaPTgyq7VI5lKy5nCoIuAhKfAMim6Wv6XkLO0eamXDSzleCAkV
A4X14fwFB1lTh07h/rITsqnLlzmSivov243lXwIDAQABAoIBAAIsjpOLxQplAOvb
Uo8pQFyMrsBIj5ETY/KSsWpPv/548TgotZgU+lrNkomwXlkcyNpSh/MnteYVnhrN
KGgCTWOYKreGgqn0IpZ62V83pyaxzQnXw/QZz5buZ3KM5IE8mvPDWlVouCIdu/XD
7/OuIHzL+kUowHg5sBed1ObwmAu+D4ASld+Hey0cz4Vo2am3jIYigSju/9P5rpg0
m0tzIzDHkTRVS2j/2mxROPSDMtx79bH7XyqP7bWwP5ohAIHLuBCmNDotAlrwS5/S
5uHwuUHapK5UnhSk0E1Ljzj6Uj1Y16OxodsW0wWvckiFZyVCTqzVWDUfAGbY8Yy/
hv05BsECgYEA7+71Brxeoam3KY4qF9zGzFi6l0ovqXboXk7JZ/IgquYb8xrNC99h
K4wOts8eYYQInJGFv2nowjqqMh1R6ALKPudf0QLNvXiQjmP/hViXoYLLWhQZcTqh
f3XIFrFG4lKZaFfbbUTB8c4hqjyhaGALzZdIOecguc5Eekgd8rHT+FECgYEAyZ7F
6s2UR+eNHi37NDQrjBLcjCF2jYxoCCwDl9IqxPCUXkmoiqklGNnoJPDfHUcMq/mC
hQjfGVBXEfxQy5BWBn/azNHoCxtffWyIqaJabR9eO/pON2zyaso0ePD1Cy9CmHoa
HadyfiH0K0UNl2f1Awpgq3Y+iVkjIo0wh5pxRq8CgYEAlN5oC4jfEmFyMwdxWKL0
eh/nji1Ki1Qq8zDhSGx0FnV2DA2qAd7UtKdPDeBO0mSQz0x/dveoorKxnSySAGmS
wRrgWZfqvc/LqX2kMkF4u46iy75C1v1w7NvQjTvrZkunwZUZoZ+S0ox6WN0LrO5D
BIoEF2Ev7flshY6vfkEV6zECgYBDqojMHADW/Qxsg4waYiP3V+EzGov6R5Qmofb2
vi9id0ekOV5aYxgzNfbmZvzKi6ziDtRSJ78QdNk0DRVkrGViuwhI023oRGCQ7JsV
K4rjsrJiuMgFbAgT9RcVO/FRtqPIHrqjFy6izGxxFTTRiq89PP9irEWivQrArtgJ
urinuwKBgQCnXeqv8R4Rc3AVYK4PPGhkJHdO603HLwyWKjZaTT5voHUr19gQs9uW
WW+XkxRkmQ3GiAFzrwM/aI/86E2+ZNQNHvKQ+3MYh0/npuJgumszNWlmwWfxZV5o
VLzTE2sMc4ivGY2f9WcCvOIVXwYnKbDOTDJ0GicdWPljnRsZSNBxKQ==
-----END RSA PRIVATE KEY-----`
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
			exp:  &Config{},
		},
		{
			name: "HappyPath",
			new: []byte(fmt.Sprintf(`{"%s":%d, "%s":%d}`,
				keyAppID, testAppID1, keyInsID, testInsID1)),
			exp: &Config{
				AppID: testAppID1,
				InsID: testInsID1,
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
			BaseURL: testBaseURL,
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
			BaseURL: testBaseURL,
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
