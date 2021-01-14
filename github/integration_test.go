// +build integration

package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"gotest.tools/assert"

	is "gotest.tools/assert/cmp"
)

// The number of requests to make to Vault during race testing.
const racynessRequests = 1000

var (
	// Overridable Vault target.
	vaultAddr  = envStrOrDefault("VAULT_ADDR", "http://127.0.0.1:8200")
	vaultToken = envStrOrDefault("VAULT_TOKEN", "root")

	// Overridable GitHub App configuration.
	appID   = envIntOrDefault(keyAppID, testAppID1)
	insID   = envIntOrDefault(keyInsID, testInsID1)
	prvKey  = envStrOrDefault(keyPrvKey, testPrvKeyValid)
	baseURL = envStrOrDefault(keyBaseURL, "")

	// Whether or not we are stubbing the GitHub API for this integration test
	// run. False when the BASE_URL environment variable has been passed.
	githubAPIStubbed bool
)

// TestIntegration is an acceptance test that performs a series of happy path
// operations against a real deployment of Vault and (optionally) GitHub.
func TestIntegration(t *testing.T) {
	// NOTE: the subtests are run sequentially as they depend on state.
	t.Parallel()

	if baseURL == "" {
		// Take control of the upstream GitHub API by stubbing it.
		githubAPIStubbed = true

		ts := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				// Always ensure auth details are being passed to GitHub.
				assert.Assert(t, r.Header.Get("Authorization") != "")

				// Handle revocation requests.
				if r.URL.Path == "/installation/token" {
					w.WriteHeader(http.StatusNoContent)
					return
				}

				// Otherwise handle creation requests.

				// If there's body content then the request has been constrained
				// by repository IDs and permissions.
				var reqBody map[string]interface{}
				assert.NilError(t, json.NewDecoder(r.Body).Decode(&reqBody))
				_, reqHasPerms := reqBody[keyPerms]
				_, reqHasRepos := reqBody[keyRepoIDs]
				retPermsRepos := reqHasPerms && reqHasRepos
				if retPermsRepos {
					// Ensure GitHub would have received the constraints sent.
					reqPerms := reqBody[keyPerms].(map[string]interface{})
					assert.Equal(t, len(reqPerms), len(testPerms))
					reqRepoIDs := reqBody[keyRepoIDs].([]interface{})
					assert.Equal(t, len(reqRepoIDs), 2)
				}

				var resBody []byte
				if retPermsRepos {
					resBody, _ = json.Marshal(map[string]interface{}{
						"token":       testToken,
						"expires_at":  testTokenExp,
						"permissions": testPerms,
						"repositories": []map[string]interface{}{
							{"id": testRepoID1},
							{"id": testRepoID2},
						},
					})
				} else {
					resBody, _ = json.Marshal(map[string]interface{}{
						"token":      testToken,
						"expires_at": testTokenExp,
					})
				}
				w.WriteHeader(http.StatusCreated)
				w.Write(resBody)
			}),
		)
		defer ts.Close()
		baseURL = ts.URL
	}

	t.Run("WriteConfig", testWriteConfig)
	t.Run("ReadConfig", testReadConfig)
	t.Run("CreateToken", testCreateToken)
	t.Run("RevokeTokens", testRevokeTokens)
	t.Run("CreateTokenWithConstraints", testCreateTokenWithConstraints)
	t.Run("WriteReadConfigCreateTokenWithRacyness", func(t *testing.T) {
		if !githubAPIStubbed || testing.Short() {
			// We do not want to smash the real GitHub API, nor do we want to
			// delay a deliberately short test run.
			t.SkipNow()
		}

		// Update the config and create tokens as quickly as possible.
		var (
			wg    sync.WaitGroup
			start = make(chan struct{})
			race  = func(testFunc func(t *testing.T)) {
				defer wg.Done()
				<-start
				for i := 0; i < racynessRequests; i++ {
					testFunc(t)
				}
			}
		)
		wg.Add(4)
		go race(testWriteConfig)
		go race(testReadConfig)
		go race(testCreateToken)
		go race(testCreateTokenWithConstraints)
		close(start)
		wg.Wait()
	})
	t.Run("DeleteConfig", func(t *testing.T) {
		// Delete.
		res, err := vaultDo(
			http.MethodDelete,
			fmt.Sprintf("/v1/github/%s", pathPatternConfig),
			nil,
		)
		assert.NilError(t, err)
		defer res.Body.Close()
		assert.Assert(t, statusCode(res.StatusCode).Successful())

		// Confirm deleted with a read.
		res, err = vaultDo(
			http.MethodGet,
			fmt.Sprintf("/v1/github/%s", pathPatternConfig),
			nil,
		)
		assert.NilError(t, err)
		defer res.Body.Close()
		assert.Assert(t, statusCode(res.StatusCode).Successful())

		var resBody map[string]interface{}
		err = json.NewDecoder(res.Body).Decode(&resBody)
		assert.NilError(t, err)
		assert.Assert(t, is.Contains(resBody, "data"))

		// Ensure default values post-delete.
		resData := resBody["data"].(map[string]interface{})
		assert.Equal(t, resData[keyAppID], 0.0)
		assert.Equal(t, resData[keyInsID], 0.0)
		assert.Equal(t, resData[keyBaseURL], githubPublicAPI)
	})
}

func testWriteConfig(t *testing.T) {
	t.Helper()

	res, err := vaultDo(
		http.MethodPost,
		fmt.Sprintf("/v1/github/%s", pathPatternConfig),
		map[string]interface{}{
			keyAppID:   appID,
			keyInsID:   insID,
			keyPrvKey:  prvKey,
			keyBaseURL: baseURL,
		},
	)
	assert.NilError(t, err)
	defer res.Body.Close()
	assert.Assert(t, statusCode(res.StatusCode).Successful())
}

func testReadConfig(t *testing.T) {
	t.Helper()

	res, err := vaultDo(
		http.MethodGet,
		fmt.Sprintf("/v1/github/%s", pathPatternConfig),
		nil,
	)
	assert.NilError(t, err)
	defer res.Body.Close()
	assert.Assert(t, statusCode(res.StatusCode).Successful())

	var resBody map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&resBody)
	assert.NilError(t, err)
	assert.Assert(t, is.Contains(resBody, "data"))

	resData := resBody["data"].(map[string]interface{})
	assert.Equal(t, resData[keyAppID], float64(appID))
	assert.Equal(t, resData[keyInsID], float64(insID))
	assert.Equal(t, resData[keyBaseURL], baseURL)
}

func testCreateToken(t *testing.T) {
	t.Helper()

	res, err := vaultDo(
		http.MethodPost,
		fmt.Sprintf("/v1/github/%s", pathPatternToken),
		nil,
	)
	assert.NilError(t, err)
	defer res.Body.Close()
	assert.Assert(t, statusCode(res.StatusCode).Successful())

	var resBody map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&resBody)
	assert.NilError(t, err)
	assert.Assert(t, is.Contains(resBody, "data"))

	resData := resBody["data"].(map[string]interface{})
	if githubAPIStubbed {
		assert.Equal(t, resData["token"], testToken)
		assert.Equal(t, resData["expires_at"], testTokenExp)
	} else {
		assert.Assert(t, resData["token"] != "")
		assert.Assert(t, resData["expires_at"] != "")
	}
}

func testRevokeTokens(t *testing.T) {
	t.Helper()

	res, err := vaultDo(
		http.MethodPut,
		fmt.Sprintf("/v1/sys/leases/revoke-prefix/github/%s", pathPatternToken),
		nil,
	)
	assert.NilError(t, err)
	defer res.Body.Close()
	assert.Assert(t, statusCode(res.StatusCode).Successful())
}

func testCreateTokenWithConstraints(t *testing.T) {
	t.Helper()

	if !githubAPIStubbed {
		// We cannot validate constraints when using the real GitHub API
		// during acceptance testing because we are not in control of the
		// repository IDs and scopes available to the GitHub App install.
		t.SkipNow()
	}

	res, err := vaultDo(
		http.MethodPost,
		fmt.Sprintf("/v1/github/%s", pathPatternToken),
		map[string]interface{}{
			keyRepoIDs: []int{testRepoID1, testRepoID2},
			keyPerms:   testPerms,
		},
	)
	assert.NilError(t, err)
	defer res.Body.Close()
	assert.Assert(t, statusCode(res.StatusCode).Successful())

	var resBody map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&resBody)
	assert.NilError(t, err)
	assert.Assert(t, is.Contains(resBody, "data"))

	resData := resBody["data"].(map[string]interface{})
	if githubAPIStubbed {
		assert.Equal(t, resData["token"], testToken)
		assert.Equal(t, resData["expires_at"], testTokenExp)
	} else {
		assert.Assert(t, resData["token"] != "")
		assert.Assert(t, resData["expires_at"] != "")
	}
}

func vaultDo(method, endpoint string, body map[string]interface{}) (res *http.Response, err error) {
	var req *http.Request
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}

		req, err = http.NewRequest(method, vaultAddr+endpoint, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
	} else {
		req, err = http.NewRequest(method, vaultAddr+endpoint, nil)
		if err != nil {
			return nil, err
		}
	}
	req.Header.Set("X-Vault-Token", vaultToken)
	return http.DefaultClient.Do(req)
}

func envStrOrDefault(key, defaultValue string) string {
	if value := os.Getenv(strings.ToUpper(key)); value != "" {
		return value
	}
	return defaultValue
}

func envIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(strings.ToUpper(key)); value != "" {
		if valueInt, err := strconv.Atoi(value); err == nil {
			return valueInt
		}
	}
	return defaultValue
}
