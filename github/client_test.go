package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"

	is "gotest.tools/assert/cmp"
)

const (
	testRepoID1 = 82455030
	testRepoID2 = 69857131
	testToken   = "v1.68d5ad1bb7d25ef98b6a6519a38e0ff559725827"
)

var (
	testPath     = fmt.Sprintf("app/installations/%v/access_tokens", testInsID1)
	testTokenExp = time.Now().Add(time.Minute * 10).Format("2019-11-19T11:01:54Z")
	testPerms    = map[string]string{
		"deployments":   "read",
		"pull_requests": "write",
	}
)

func TestNewClient(t *testing.T) {
	t.Parallel()

	var cases = []struct {
		name string
		conf *Config
		err  error
		url  string
	}{
		{
			name: "Empty",
			err:  errClientConfigNil,
		},
		{
			name: "HappyPath",
			conf: &Config{
				AppID:   testAppID1,
				InsID:   testInsID1,
				PrvKey:  testPrvKeyValid,
				BaseURL: testBaseURLValid,
			},
			url: fmt.Sprintf("%s%s", testBaseURLValid, testPath),
		},
		{
			name: "InvalidPrvKey",
			conf: &Config{
				AppID:  testAppID1,
				InsID:  testInsID1,
				PrvKey: "not a valid private key",
			},
			err: errors.New("private key"),
		},
		{
			name: "InvalidBaseURL",
			conf: &Config{
				AppID:   testAppID1,
				InsID:   testInsID1,
				PrvKey:  testPrvKeyValid,
				BaseURL: testBaseURLInvalid,
			},
			err: errors.New("parse"),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := NewClient(tc.conf)
			if tc.err != nil {
				assert.ErrorContains(t, err, tc.err.Error())
				assert.Assert(t, is.Nil(c))
			} else {
				assert.NilError(t, err)
				assert.Assert(t, c != nil)
				assert.Equal(t, c.url.String(), tc.url)
			}
		})
	}
}

func TestClient_Token(t *testing.T) {
	t.Parallel()

	var cases = []struct {
		name    string
		reqData *framework.FieldData
		handler http.HandlerFunc
		res     *logical.Response
		ctx     context.Context
		err     error
	}{
		{
			name: "HappyPath",
			ctx:  context.Background(),
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				assert.Equal(t, r.Method, http.MethodPost)
				assert.Equal(t, r.URL.Path, fmt.Sprintf("/%s", testPath))
				assert.Assert(t, r.Header.Get("Authorization") != "")

				w.Header().Set("Content-Type", "application/json")
				body, _ := json.Marshal(map[string]interface{}{
					"token":      testToken,
					"expires_at": testTokenExp,
				})
				w.WriteHeader(http.StatusCreated)
				w.Write(body)
			}),
			res: &logical.Response{
				Data: map[string]interface{}{
					"token":      testToken,
					"expires_at": testTokenExp,
				},
			},
		},
		{
			name: "HappyPathWithTokenConstraints",
			ctx:  context.Background(),
			reqData: &framework.FieldData{
				Raw: map[string]interface{}{
					keyRepoIDs: []int{testRepoID1, testRepoID2},
					keyPerms:   testPerms,
				},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				assert.Equal(t, r.Method, http.MethodPost)
				assert.Equal(t, r.URL.Path, fmt.Sprintf("/%s", testPath))
				assert.Assert(t, r.Header.Get("Authorization") != "")

				var reqBody map[string]interface{}
				assert.NilError(t, json.NewDecoder(r.Body).Decode(&reqBody))
				assert.Assert(t, is.Contains(reqBody, keyPerms))
				assert.Assert(t, is.Contains(reqBody, keyRepoIDs))

				w.Header().Set("Content-Type", "application/json")
				body, _ := json.Marshal(map[string]interface{}{
					"token":       testToken,
					"expires_at":  testTokenExp,
					"permissions": testPerms,
					"repositories": []map[string]interface{}{
						{"id": testRepoID1},
						{"id": testRepoID2},
					},
				})
				w.WriteHeader(http.StatusCreated)
				w.Write(body)
			}),
			res: &logical.Response{
				Data: map[string]interface{}{
					"token":       testToken,
					"expires_at":  testTokenExp,
					"permissions": testPerms,
					"repositories": []map[string]interface{}{
						{"id": testRepoID1},
						{"id": testRepoID2},
					},
				},
			},
		},
		{
			// All Token() requests should be part of an existing RPC against
			// the configured Vault path.
			name: "NilContext",
			err:  errors.New(fmtErrUnableToBuildAccessTokenReq),
		},
		{
			name: "EOFResponse",
			ctx:  context.Background(),
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()
				// Simulate an empty response.
			}),
			err: errors.New(fmtErrUnableToDecodeAccessTokenRes),
		},
		{
			name: "EmptyResponse",
			ctx:  context.Background(),
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()
				w.WriteHeader(http.StatusOK)
			}),
			err: errors.New(fmtErrUnableToDecodeAccessTokenRes),
		},
		{
			name: "4xxResponse",
			ctx:  context.Background(),
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()
				// 422 is the most likely GitHub Apps API 4xx response (when
				// presented with valid auth) and it occurs when the user has
				// requested token permissions or repositories the installation
				// does not have scope over.
				w.WriteHeader(http.StatusUnprocessableEntity)
			}),
			err: errors.New(fmtErrUnableToCreateAccessToken),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(tc.handler)
			defer ts.Close()

			client, err := NewClient(&Config{
				AppID:   testAppID1,
				InsID:   testInsID1,
				PrvKey:  testPrvKeyValid,
				BaseURL: ts.URL,
			})
			assert.NilError(t, err)

			res, err := client.Token(tc.ctx, tc.reqData)

			if tc.err != nil {
				assert.ErrorContains(t, err, tc.err.Error())
			} else {
				assert.NilError(t, err)
			}

			if tc.res != nil && tc.res.Data != nil {
				assert.Equal(t, res.Data["expires_at"], tc.res.Data["expires_at"])
				assert.Equal(t, res.Data["token"], tc.res.Data["token"])

				if _, ok := tc.res.Data["permissions"]; ok {
					testPerms := tc.res.Data["permissions"].(map[string]string)
					resPerms := res.Data["permissions"].(map[string]interface{})
					assert.Equal(t, len(resPerms), len(testPerms))
				}

				if _, ok := tc.res.Data["repositories"]; ok {
					testRepos := tc.res.Data["repositories"].([]map[string]interface{})
					resRepos := res.Data["repositories"].([]interface{})
					assert.Equal(t, len(resRepos), len(testRepos))
				}
				assert.Equal(t, res.Data["token"], tc.res.Data["token"])
			}
		})
	}
}
