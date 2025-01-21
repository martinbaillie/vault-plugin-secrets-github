package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"
)

const installationsJSON = `
[
  {
    "id": 1,
    "account": {
      "login": "octocat",
      "id": 1,
      "node_id": "MDQ6VXNlcjE=",
      "avatar_url": "https://github.com/images/error/octocat_happy.gif",
      "gravatar_id": "",
      "url": "https://api.github.com/users/octocat",
      "html_url": "https://github.com/octocat",
      "followers_url": "https://api.github.com/users/octocat/followers",
      "following_url": "https://api.github.com/users/octocat/following{/other_user}",
      "gists_url": "https://api.github.com/users/octocat/gists{/gist_id}",
      "starred_url": "https://api.github.com/users/octocat/starred{/owner}{/repo}",
      "subscriptions_url": "https://api.github.com/users/octocat/subscriptions",
      "organizations_url": "https://api.github.com/users/octocat/orgs",
      "repos_url": "https://api.github.com/users/octocat/repos",
      "events_url": "https://api.github.com/users/octocat/events{/privacy}",
      "received_events_url": "https://api.github.com/users/octocat/received_events",
      "type": "User",
      "site_admin": false
    },
    "access_tokens_url": "https://api.github.com/app/installations/1/access_tokens",
    "repositories_url": "https://api.github.com/installation/repositories",
    "html_url": "https://github.com/organizations/github/settings/installations/1",
    "app_id": 1,
    "target_id": 1,
    "target_type": "Organization",
    "permissions": {
      "checks": "write",
      "metadata": "read",
      "contents": "read"
    },
    "events": [
      "push",
      "pull_request"
    ],
    "single_file_name": "config.yaml",
    "has_multiple_single_files": true,
    "single_file_paths": [
      "config.yml",
      ".github/issue_TEMPLATE.md"
    ],
    "repository_selection": "selected",
    "created_at": "2017-07-08T16:18:44-04:00",
    "updated_at": "2017-07-08T16:18:44-04:00",
    "app_slug": "github-actions",
    "suspended_at": null,
    "suspended_by": null
  }
]
`

func testBackendPathInstallations(t *testing.T, op logical.Operation) {
	t.Helper()

	t.Run("HappyPath", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		ts := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()

				w.WriteHeader(http.StatusOK)
				w.Write([]byte(installationsJSON))
			}),
		)
		defer ts.Close()

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      pathPatternConfig,
			Data: map[string]any{
				keyAppID:   testAppID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      pathPatternInstallations,
		})
		assert.NilError(t, err)

		assert.Assert(t, r != nil)
		assert.Assert(t, len(r.Data) > 0)
	})

	t.Run("FailedClient", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t, failVerbRead)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      pathPatternInstallations,
		})
		assert.ErrorContains(t, err, errConfRetrieval.Error())
		assert.Assert(t, r == nil)
	})

	t.Run("FailedInstallationsRequest", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		ts := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				t.Helper()
				w.WriteHeader(http.StatusInternalServerError)
			}),
		)
		defer ts.Close()

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      pathPatternConfig,
			Data: map[string]any{
				keyAppID:   testAppID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: op,
			Path:      pathPatternInstallations,
		})
		assert.ErrorContains(t, err, "500 Internal Server Error")
		assert.Assert(t, r == nil)
	})

	t.Run("Pagination", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		firstPage := `[{
		    "id": 1,
		    "account": {
		    "login": "octocat",
		    "id": 1
		    }
		}]`

		secondPage := `[{
		    "id": 2,
		    "account": {
		    "login": "octodog",
		    "id": 2
		    }
		}]`

		var ts *httptest.Server
		ts = httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				t.Helper()

				linkHeader := `<` + ts.URL + `?page=2>; rel="next"`
				if r.URL.Query().Get("page") == "2" {
					linkHeader = ``
				}
				w.Header().Set("Link", linkHeader)

				switch r.URL.Query().Get("page") {
				case "2":
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(secondPage))
				default:
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(firstPage))
				}
			}),
		)
		defer ts.Close()

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.CreateOperation,
			Path:      pathPatternConfig,
			Data: map[string]any{
				keyAppID:   testAppID1,
				keyPrvKey:  testPrvKeyValid,
				keyBaseURL: ts.URL,
			},
		})
		assert.NilError(t, err)

		r, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      pathPatternInstallations,
		})
		assert.NilError(t, err)

		// Ensure both pages were combined correctly.
		assert.Assert(t, r != nil)
		assert.Assert(t, len(r.Data) == 2)
		assert.Equal(t, r.Data["octocat"], 1)
		assert.Equal(t, r.Data["octodog"], 2)
	})
}

func TestBackend_PathInstallationsRead(t *testing.T) {
	t.Parallel()
	testBackendPathInstallations(t, logical.ReadOperation)
}
