package github

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"

	is "gotest.tools/assert/cmp"
)

// skipFixture is a fake GitHub API for exercising the skip-inaccessible flow.
type skipFixture struct {
	// goneRepos are rejected by the access token endpoint (422) when
	// requested, and answered with 404 by the repository installation probe.
	goneRepos map[string]bool
	// probeStatus overrides the probe response status for a repository.
	probeStatus map[string]int
	// tokenStatus overrides the access token response status for every POST.
	tokenStatus int
	// tokenMessage is the message body served with tokenStatus.
	tokenMessage string
	// installations is the installation list served at /app/installations.
	installations []map[string]any

	mu           sync.Mutex
	tokenCalls   atomic.Int32
	probeCalls   atomic.Int32
	listCalls    atomic.Int32
	probePaths   []string
	lastRequests [][]string
}

func (f *skipFixture) handler(t *testing.T) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodPost && r.URL.Path == fmt.Sprintf("/%s", testPath):
			f.tokenCalls.Add(1)

			var body tokenConstraints
			assert.NilError(t, json.NewDecoder(r.Body).Decode(&body))

			f.mu.Lock()
			f.lastRequests = append(f.lastRequests, body.Repositories)
			f.mu.Unlock()

			if f.tokenStatus != 0 {
				w.WriteHeader(f.tokenStatus)
				msg, _ := json.Marshal(map[string]string{"message": cmp.Or(f.tokenMessage, "forced")})
				w.Write(msg)

				return
			}

			for _, repo := range body.Repositories {
				if f.goneRepos[repo] {
					w.WriteHeader(http.StatusUnprocessableEntity)
					w.Write([]byte(`{"message":"There is at least one repository that does not exist ` +
						`or is not accessible to the parent installation."}`))

					return
				}
			}

			w.WriteHeader(http.StatusCreated)
			out, _ := json.Marshal(map[string]any{"token": testToken, "expires_at": testTokenExp})
			w.Write(out)

		case r.Method == http.MethodGet && r.URL.Path == "/app/installations":
			f.listCalls.Add(1)

			out, _ := json.Marshal(f.installations)
			w.Write(out)

		case r.Method == http.MethodGet &&
			strings.HasPrefix(r.URL.Path, "/repos/") &&
			strings.HasSuffix(r.URL.Path, "/installation"):
			f.probeCalls.Add(1)
			assert.Assert(t, r.Header.Get("Authorization") != "")

			f.mu.Lock()
			f.probePaths = append(f.probePaths, r.URL.Path)
			f.mu.Unlock()

			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			repo := parts[2]

			if status, ok := f.probeStatus[repo]; ok {
				w.WriteHeader(status)

				return
			}

			if f.goneRepos[repo] {
				w.WriteHeader(http.StatusNotFound)

				return
			}

			w.Write([]byte(`{"id":1}`))

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func TestClient_Token_SkipInaccessibleRepositories(t *testing.T) {
	t.Parallel()

	var (
		okInstallations = []map[string]any{
			{"id": testInsID1, "account": map[string]any{"login": testOrgName1}},
		}
		repos = []string{"alpha", "gone", "beta"}
	)

	cases := []struct {
		name        string
		skip        bool
		tokReq      *tokenRequest
		fixture     *skipFixture
		err         string
		skipped     []string
		tokenCalls  int32
		probeCalls  int32
		listCalls   int32
		lastRequest []string
	}{
		{
			name:       "DisabledReturnsOriginalError",
			skip:       false,
			tokReq:     &tokenRequest{OrgName: testOrgName1, InstallationID: testInsID1, tokenConstraints: tokenConstraints{Repositories: repos}},
			fixture:    &skipFixture{goneRepos: map[string]bool{"gone": true}},
			err:        "does not exist or is not accessible",
			tokenCalls: 1,
		},
		{
			name:        "DropsInaccessibleAndRetries",
			skip:        true,
			tokReq:      &tokenRequest{OrgName: testOrgName1, InstallationID: testInsID1, tokenConstraints: tokenConstraints{Repositories: repos}},
			fixture:     &skipFixture{goneRepos: map[string]bool{"gone": true}},
			skipped:     []string{"gone"},
			tokenCalls:  2,
			probeCalls:  3,
			lastRequest: []string{"alpha", "beta"},
		},
		{
			name:       "AllRequestedAccessibleButStill422ReturnsOriginalError",
			skip:       true,
			tokReq:     &tokenRequest{OrgName: testOrgName1, InstallationID: testInsID1, tokenConstraints: tokenConstraints{Repositories: []string{"alpha"}}},
			fixture:    &skipFixture{tokenStatus: http.StatusUnprocessableEntity, tokenMessage: "repository not accessible"},
			err:        "not accessible",
			tokenCalls: 1,
			probeCalls: 1,
		},
		{
			name:       "Other422DoesNotProbe",
			skip:       true,
			tokReq:     &tokenRequest{OrgName: testOrgName1, InstallationID: testInsID1, tokenConstraints: tokenConstraints{Repositories: repos}},
			fixture:    &skipFixture{tokenStatus: http.StatusUnprocessableEntity, tokenMessage: "permissions requested exceed the installation"},
			err:        "permissions requested",
			tokenCalls: 1,
		},
		{
			name:       "NoneAccessibleReturnsError",
			skip:       true,
			tokReq:     &tokenRequest{OrgName: testOrgName1, InstallationID: testInsID1, tokenConstraints: tokenConstraints{Repositories: []string{"gone", "gone2"}}},
			fixture:    &skipFixture{goneRepos: map[string]bool{"gone": true, "gone2": true}},
			err:        string(errNoAccessibleRepositories),
			tokenCalls: 1,
			probeCalls: 2,
		},
		{
			name:       "ProbeErrorReturnsOriginalError",
			skip:       true,
			tokReq:     &tokenRequest{OrgName: testOrgName1, InstallationID: testInsID1, tokenConstraints: tokenConstraints{Repositories: repos}},
			fixture:    &skipFixture{goneRepos: map[string]bool{"gone": true}, probeStatus: map[string]int{"beta": http.StatusInternalServerError}},
			err:        "does not exist or is not accessible",
			tokenCalls: 1,
			probeCalls: 3,
		},
		{
			name:       "SuccessfulFirstAttemptMakesNoProbes",
			skip:       true,
			tokReq:     &tokenRequest{OrgName: testOrgName1, InstallationID: testInsID1, tokenConstraints: tokenConstraints{Repositories: []string{"alpha", "beta"}}},
			fixture:    &skipFixture{},
			tokenCalls: 1,
		},
		{
			name:        "ResolvesOrgFromInstallationWhenMissing",
			skip:        true,
			tokReq:      &tokenRequest{InstallationID: testInsID1, tokenConstraints: tokenConstraints{Repositories: repos}},
			fixture:     &skipFixture{goneRepos: map[string]bool{"gone": true}, installations: okInstallations},
			skipped:     []string{"gone"},
			tokenCalls:  2,
			probeCalls:  3,
			listCalls:   1,
			lastRequest: []string{"alpha", "beta"},
		},
		{
			name:       "UnknownInstallationReturnsOriginalError",
			skip:       true,
			tokReq:     &tokenRequest{InstallationID: testInsID1, tokenConstraints: tokenConstraints{Repositories: repos}},
			fixture:    &skipFixture{goneRepos: map[string]bool{"gone": true}, installations: []map[string]any{}},
			err:        "does not exist or is not accessible",
			tokenCalls: 1,
			listCalls:  1,
		},
		{
			name:       "RepositoryIDsAreNotFiltered",
			skip:       true,
			tokReq:     &tokenRequest{OrgName: testOrgName1, InstallationID: testInsID1, tokenConstraints: tokenConstraints{RepositoryIDs: []int{testRepoID1}}},
			fixture:    &skipFixture{tokenStatus: http.StatusUnprocessableEntity},
			err:        "forced",
			tokenCalls: 1,
		},
		{
			name:       "OtherClientErrorsAreNotRetried",
			skip:       true,
			tokReq:     &tokenRequest{OrgName: testOrgName1, InstallationID: testInsID1, tokenConstraints: tokenConstraints{Repositories: repos}},
			fixture:    &skipFixture{tokenStatus: http.StatusForbidden},
			err:        "forced",
			tokenCalls: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(tc.fixture.handler(t))
			defer ts.Close()

			client, err := NewClient(&Config{
				AppID:   testAppID1,
				PrvKey:  testPrvKeyValid,
				BaseURL: ts.URL,
			})
			assert.NilError(t, err)

			tc.tokReq.SkipInaccessibleRepositories = tc.skip

			original := append([]string(nil), tc.tokReq.Repositories...)

			res, err := client.Token(context.Background(), tc.tokReq)

			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)
				assert.Assert(t, is.Nil(res))
			} else {
				assert.NilError(t, err)
				assert.Equal(t, res.Data["token"], testToken)

				if tc.skipped != nil {
					assert.DeepEqual(t, res.Data["skipped_repositories"], tc.skipped)
				} else {
					_, present := res.Data["skipped_repositories"]
					assert.Assert(t, !present)
				}
			}

			assert.Equal(t, tc.fixture.tokenCalls.Load(), tc.tokenCalls)
			assert.Equal(t, tc.fixture.probeCalls.Load(), tc.probeCalls)
			assert.Equal(t, tc.fixture.listCalls.Load(), tc.listCalls)

			// The caller's request must never be modified by the retry.
			assert.DeepEqual(t, tc.tokReq.Repositories, original)

			if tc.lastRequest != nil {
				last := tc.fixture.lastRequests[len(tc.fixture.lastRequests)-1]
				assert.DeepEqual(t, last, tc.lastRequest)
			}

			for _, p := range tc.fixture.probePaths {
				assert.Assert(t, strings.HasPrefix(p, "/repos/"+testOrgName1+"/"), p)
			}
		})
	}
}

func TestPermissionSet_SkipInaccessibleRepositories(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		data map[string]any
		want bool
	}{
		{"DefaultsToFalse", map[string]any{keyInstallationID: testInsID1}, false},
		{"OptIn", map[string]any{keyInstallationID: testInsID1, keySkipInaccessibleRepositories: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b, storage := testBackend(t)

			_, err := b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "permissionset/foo",
				Data:      tc.data,
			})
			assert.NilError(t, err)

			res, err := b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: logical.ReadOperation,
				Path:      "permissionset/foo",
			})
			assert.NilError(t, err)
			assert.Equal(t, res.Data[keySkipInaccessibleRepositories], tc.want)

			ps, err := getPermissionSet(context.Background(), "foo", storage)
			assert.NilError(t, err)
			assert.Equal(t, ps.TokenRequest.SkipInaccessibleRepositories, tc.want)
		})
	}
}
