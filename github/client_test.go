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

	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"

	is "gotest.tools/assert/cmp"
)

const (
	testRepo1   = "vault-plugin-secrets-github"
	testRepo2   = "hashitalkaunz"
	testRepoID1 = 223704264
	testRepoID2 = 360447594
	testToken   = "ghs_1aRGyjpfMQ98l0rnji5dstEEg10rOY3lenzG"
)

var (
	testPath     = fmt.Sprintf("app/installations/%v/access_tokens", testInsID1)
	testTokenExp = time.Now().Add(time.Minute * 10).Format(time.RFC3339)
	testPerms    = map[string]string{
		"deployments":   "read",
		"pull_requests": "write",
	}
)

// Force errors in a round trip.
type doomedRoundTrip struct{ err error }

func (d *doomedRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, d.err
}

func TestNewClient(t *testing.T) {
	t.Parallel()

	cases := []struct {
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
				PrvKey:  testPrvKeyValid,
				BaseURL: testBaseURLValid,
			},
			url: fmt.Sprintf("%s/%s", testBaseURLValid, testPath),
		},
		{
			name: "InvalidPrvKey",
			conf: &Config{
				AppID:  testAppID1,
				PrvKey: "not a valid private key",
			},
			err: errors.New("private key"),
		},
		{
			name: "InvalidBaseURL",
			conf: &Config{
				AppID:   testAppID1,
				PrvKey:  testPrvKeyValid,
				BaseURL: testBaseURLInvalid,
			},
			err: errors.New("parse"),
		},
		{
			name: "UnparseableBaseURL",
			conf: &Config{
				AppID:   testAppID1,
				PrvKey:  testPrvKeyValid,
				BaseURL: "%zzzzz",
			},
			err: errors.New("parse"),
		},
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := NewClient(tc.conf)
			if tc.err != nil {
				assert.ErrorContains(t, err, tc.err.Error())
				assert.Assert(t, is.Nil(c))
			} else {
				assert.NilError(t, err)

				url, err := c.accessTokenURLForInstallationID(testInsID1)

				assert.NilError(t, err)
				assert.Assert(t, c != nil)
				assert.Equal(t, url.String(), tc.url)
			}
		})
	}
}

func TestClient_Token(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                   string
		accessTokenURLTemplate string
		transport              http.RoundTripper
		tokReq                 *tokenRequest
		handler                http.HandlerFunc
		res                    *logical.Response
		ctx                    context.Context
		err                    error
	}{
		{
			name:   "HappyPath",
			ctx:    context.Background(),
			tokReq: &tokenRequest{InstallationID: testInsID1},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				assert.Equal(t, r.Method, http.MethodPost)
				assert.Equal(t, r.URL.Path, fmt.Sprintf("/%s", testPath))
				assert.Assert(t, r.Header.Get("Authorization") != "")

				w.Header().Set("Content-Type", "application/json")
				body, _ := json.Marshal(map[string]any{
					"token":      testToken,
					"expires_at": testTokenExp,
				})
				w.WriteHeader(http.StatusCreated)
				w.Write(body)
			}),
			res: &logical.Response{
				Data: map[string]any{
					"token":           testToken,
					"installation_id": testInsID1,
					"expires_at":      testTokenExp,
				},
			},
		},
		{
			name: "HappyPathWithTokenConstraints",
			ctx:  context.Background(),
			tokReq: &tokenRequest{
				InstallationID: testInsID1,
				tokenConstraints: tokenConstraints{
					Repositories:  []string{testRepo1, testRepo2},
					RepositoryIDs: []int{testRepoID1, testRepoID2},
					Permissions:   testPerms,
				},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				assert.Equal(t, r.Method, http.MethodPost)
				assert.Equal(t, r.URL.Path, fmt.Sprintf("/%s", testPath))
				assert.Assert(t, r.Header.Get("Authorization") != "")

				var reqBody map[string]any
				assert.NilError(t, json.NewDecoder(r.Body).Decode(&reqBody))
				assert.Assert(t, is.Contains(reqBody, keyPerms))
				assert.Assert(t, is.Contains(reqBody, keyRepoIDs))
				assert.Assert(t, is.Contains(reqBody, keyRepos))

				w.Header().Set("Content-Type", "application/json")
				body, _ := json.Marshal(map[string]any{
					"token":           testToken,
					"installation_id": testInsID1,
					"expires_at":      testTokenExp,
					"permissions":     testPerms,
					"repositories": []map[string]any{
						{"id": testRepoID1, "name": testRepo1},
						{"id": testRepoID2, "name": testRepo2},
					},
				})
				w.WriteHeader(http.StatusCreated)
				w.Write(body)
			}),
			res: &logical.Response{
				Data: map[string]any{
					"token":           testToken,
					"installation_id": testInsID1,
					"expires_at":      testTokenExp,
					"permissions":     testPerms,
					"repositories": []map[string]any{
						{"id": testRepoID1, "name": testRepo1},
						{"id": testRepoID2, "name": testRepo2},
					},
				},
			},
		},
		{
			name: "MissingTokenReq",
			ctx:  context.Background(),
			err:  errMissingTokenReq,
		},
		{
			name:      "FailedRoundTrip",
			ctx:       context.Background(),
			tokReq:    &tokenRequest{InstallationID: testInsID1},
			transport: &doomedRoundTrip{errors.New("failed RT")},
			err:       errors.New("failed RT"),
		},
		{
			name:                   "UnparseableAccessTokenURL",
			ctx:                    context.Background(),
			tokReq:                 &tokenRequest{InstallationID: testInsID1},
			accessTokenURLTemplate: "%zzzzz",
			err:                    errors.New("parse"),
		},
		{
			// All Token() requests should be part of an existing RPC against
			// the configured Vault path.
			name:   "NilContext",
			tokReq: &tokenRequest{InstallationID: testInsID1},
			err:    errUnableToBuildAccessTokenReq,
		},
		{
			name:   "EOFResponse",
			ctx:    context.Background(),
			tokReq: &tokenRequest{InstallationID: testInsID1},
			handler: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				t.Helper()
				// Simulate an empty response.
			}),
			err: errUnableToDecodeAccessTokenRes,
		},
		{
			name:   "ErrorInError",
			ctx:    context.Background(),
			tokReq: &tokenRequest{InstallationID: testInsID1},
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()
				w.Header().Set("Content-Length", "1")
				w.WriteHeader(http.StatusForbidden)
			}),
			err: errUnableToCreateAccessToken,
		},
		{
			name: "EmptyResponse",
			ctx:  context.Background(),
			tokReq: &tokenRequest{
				InstallationID: testInsID1,
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()
				w.WriteHeader(http.StatusOK)
			}),
			err: errUnableToDecodeAccessTokenRes,
		},
		{
			name:   "4xxResponse",
			ctx:    context.Background(),
			tokReq: &tokenRequest{InstallationID: testInsID1},
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()
				// 422 is the most likely GitHub Apps API 4xx response (when
				// presented with valid auth) and it occurs when the user has
				// requested token permissions or repositories the installation
				// does not have scope over.
				w.WriteHeader(http.StatusUnprocessableEntity)
			}),
			err: errUnableToCreateAccessToken,
		},
		{
			name:   "OrgNameExtraLookupHappyPath",
			ctx:    context.Background(),
			tokReq: &tokenRequest{OrgName: testOrgName1},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				switch r.Method {
				case http.MethodGet:
					assert.Equal(t, r.URL.Path, "/app/installations")
					assert.Assert(t, r.Header.Get("Authorization") != "")

					w.Header().Set("Content-Type", "application/json")
					body, _ := json.Marshal([]map[string]any{
						{
							"id": testInsID1,
							"account": map[string]any{
								"login": testOrgName1,
							},
						},
					})
					w.WriteHeader(http.StatusOK)
					w.Write(body)

				case http.MethodPost:
					assert.Equal(t, r.URL.Path, fmt.Sprintf("/%s", testPath))
					assert.Assert(t, r.Header.Get("Authorization") != "")

					w.Header().Set("Content-Type", "application/json")
					body, _ := json.Marshal(map[string]any{
						"token":      testToken,
						"expires_at": testTokenExp,
					})
					w.WriteHeader(http.StatusCreated)
					w.Write(body)
				}
			}),
			res: &logical.Response{
				Data: map[string]any{
					"token":           testToken,
					"installation_id": testInsID1,
					"expires_at":      testTokenExp,
				},
			},
		},
		{
			name:   "OrgNameNotInstalled",
			ctx:    context.Background(),
			tokReq: &tokenRequest{OrgName: testOrgName1},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				assert.Equal(t, r.Method, http.MethodGet)
				assert.Equal(t, r.URL.Path, "/app/installations")
				assert.Assert(t, r.Header.Get("Authorization") != "")

				w.Header().Set("Content-Type", "application/json")
				body, _ := json.Marshal([]map[string]any{
					{
						"id": testInsID1,
						"account": map[string]any{
							"login": testOrgName2,
						},
					},
				})
				w.WriteHeader(http.StatusOK)
				w.Write(body)
			}),
			err: errAppNotInstalled,
		},
		{
			name:   "OrgNameEmptyResponse",
			ctx:    context.Background(),
			tokReq: &tokenRequest{OrgName: testOrgName1},
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()
				w.WriteHeader(http.StatusOK)
			}),
			err: errUnableToDecodeInstallationsRes,
		},
		{
			name:   "OrgNameForbidden",
			ctx:    context.Background(),
			tokReq: &tokenRequest{OrgName: testOrgName1},
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()
				w.WriteHeader(http.StatusForbidden)
			}),
			err: errUnableToGetInstallations,
		},
		{
			name:   "OrgNameErrorInError",
			ctx:    context.Background(),
			tokReq: &tokenRequest{OrgName: testOrgName1},
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()
				w.Header().Set("Content-Length", "1")
				w.WriteHeader(http.StatusForbidden)
			}),
			err: errUnableToGetInstallations,
		},
		{
			name:      "OrgNameFailedRoundTrip",
			ctx:       context.Background(),
			tokReq:    &tokenRequest{OrgName: testOrgName1},
			transport: &doomedRoundTrip{errors.New("failed RT")},
			err:       errors.New("failed RT"),
		},
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(tc.handler)
			defer ts.Close()

			client, err := NewClient(&Config{
				AppID:   testAppID1,
				PrvKey:  testPrvKeyValid,
				BaseURL: ts.URL,
			})
			assert.NilError(t, err)

			if tc.accessTokenURLTemplate != "" {
				client.accessTokenURLTemplate = tc.accessTokenURLTemplate
			}

			if tc.transport != nil {
				client.installationsClient.Transport = tc.transport
			}

			res, err := client.Token(tc.ctx, tc.tokReq)

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
					resPerms := res.Data["permissions"].(map[string]any)
					assert.Equal(t, len(resPerms), len(testPerms))
				}

				if _, ok := tc.res.Data["repositories"]; ok {
					testRepos := tc.res.Data["repositories"].([]map[string]any)
					resRepos := res.Data["repositories"].([]any)
					assert.Equal(t, len(resRepos), len(testRepos))
				}
				assert.Equal(t, res.Data["token"], tc.res.Data["token"])
			}
		})
	}
}

func TestClient_RevokeToken(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                string
		token               string
		revocationTransport http.RoundTripper
		handler             http.HandlerFunc
		res                 *logical.Response
		ctx                 context.Context
		err                 error
	}{
		{
			name:  "HappyPath",
			token: testToken,
			ctx:   context.Background(),
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				assert.Equal(t, r.Method, http.MethodDelete)
				assert.Equal(t, r.URL.Path, "/installation/token")
				assert.Equal(t, r.Header.Get("Authorization"), fmt.Sprintf("Bearer %s", testToken))

				w.WriteHeader(http.StatusNoContent)
			}),
			res: &logical.Response{},
		},
		{
			// All RevokeToken() requests should be part of an existing RPC
			// against the configured Vault path.
			name: "NilContext",
			err:  errUnableToBuildAccessTokenRevReq,
		},
		{
			name: "ErrorInError",
			ctx:  context.Background(),
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()
				w.Header().Set("Content-Length", "1")
				w.WriteHeader(http.StatusForbidden)
			}),
			err: errUnableToRevokeAccessToken,
		},
		{
			name: "401Response",
			ctx:  context.Background(),
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()
				// 401 is the most likely GitHub API 4xx response when trying to revoke and it
				// occurs when the token is already expired or revoked. We treat this as a success
				// in the case of a lease revocation.
				w.WriteHeader(http.StatusUnauthorized)
			}),
			res: &logical.Response{},
		},
		{
			name: "403Response",
			ctx:  context.Background(),
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()
				w.WriteHeader(http.StatusForbidden)
			}),
			err: errUnableToRevokeAccessToken,
		},
		{
			name:                "FailedRoundTrip",
			ctx:                 context.Background(),
			revocationTransport: &doomedRoundTrip{errors.New("failed RT")},
			err:                 errors.New("failed RT"),
		},
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(tc.handler)
			defer ts.Close()

			client, err := NewClient(&Config{
				AppID:   testAppID1,
				PrvKey:  testPrvKeyValid,
				BaseURL: ts.URL,
			})
			assert.NilError(t, err)

			if tc.revocationTransport != nil {
				client.revocationClient.Transport = tc.revocationTransport
			}

			res, err := client.RevokeToken(tc.ctx, tc.token)

			if tc.err != nil {
				assert.ErrorContains(t, err, tc.err.Error())
			} else {
				assert.NilError(t, err)
			}

			assert.DeepEqual(t, res, tc.res)
		})
	}
}
