package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	errBody                           = Error("error body")
	errClientConfigNil                = Error("client configuration was nil")
	errMissingTokenReq                = Error("missing access token request")
	errParsingBaseURL                 = Error("parsing base URL")
	errUnableToBuildAccessTokenReq    = Error("unable to build access token request")
	errUnableToBuildAccessTokenRevReq = Error("unable to build access token revocation request")
	errUnableToBuildAccessTokenURL    = Error("unable to build access token URL")
	errUnableToCreateAccessToken      = Error("unable to create access token")
	errUnableToDecodeAccessTokenRes   = Error("unable to decode access token response")
	errUnableToDecodeInstallationsRes = Error("unable to decode installations list response")
	errUnableToGetInstallations       = Error("unable to get installations")
	errUnableToRevokeAccessToken      = Error("unable to revoke access token")
	errAppNotInstalled                = Error("app not installed in GitHub organization")
	errNoAccessibleRepositories       = Error("none of the requested repositories are accessible to the installation")
	errUnableToProbeRepository        = Error("unable to probe repository installation")
	errInstallationNotFound           = Error("installation not found")
)

// inaccessibleRepositoryMessage is the fragment of GitHub's 422 message for a
// repository that does not exist or is not accessible to the installation. A
// 422 is also returned for other problems, such as over-requested permissions.
const inaccessibleRepositoryMessage = "not accessible"

// uninstalledRepositoryTTL is how long a repository found uninstalled by a probe
// is remembered. A repository added to the installation is skipped until then.
const uninstalledRepositoryTTL = 60 * time.Second

// Client encapsulates an HTTP client for talking to the configured GitHub App.
type Client struct {
	*Config

	// RevocationURL is the access token revocation URL for this client.
	revocationURL *url.URL

	// revocationClient is an HTTP client used for unauthenticated GitHub App
	// installation token revocation requests.
	revocationClient *http.Client

	// installationsClient is an HTTP client used for authenticated GitHub App
	// installation token requests.
	installationsClient *http.Client

	// InstallationsURL is the installations operations URL for this client.
	installationsURL *url.URL

	// URL is the access token URL template for this client.
	accessTokenURLTemplate string

	// baseURL is the parsed base URL for GitHub API requests.
	baseURL *url.URL

	// uninstalledRepos remembers repositories a probe found uninstalled until
	// the stored expiry (a time.Time), so repeated token requests do not probe
	// them again. The client is rebuilt on a config change, which clears it.
	uninstalledRepos sync.Map
}

// NewClient returns a newly constructed client from the provided config and
// with sensible default transport settings. It will error if it fails to
// validate necessary configuration formats like URIs and PEM encoded private
// keys.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, errClientConfigNil
	}

	// A sensible request timeout.
	reqTimeout := time.Millisecond * 10000

	// Initialise a new transport instead of using Go's default. This transport
	// has explicit timeouts and sensible defaults for max connections per host
	// (i.e. their zero values—unlimited—since the plugin typically only deals
	// with one host).
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: reqTimeout / 4,
		}).DialContext,
		TLSHandshakeTimeout: reqTimeout / 4,
		Proxy:               http.ProxyFromEnvironment,
	}

	// Create an GitHub App installation authenticated clone of transport.
	authenticatedTransport, err := ghinstallation.NewAppsTransport(
		transport.Clone(),
		int64(config.AppID),
		[]byte(config.PrvKey),
	)
	if err != nil {
		return nil, err
	}

	baseURL, err := url.ParseRequestURI(config.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errParsingBaseURL, err)
	}

	installationsURL := baseURL.ResolveReference(&url.URL{Path: "app/installations"})

	return &Client{
		Config:        config,
		revocationURL: baseURL.ResolveReference(&url.URL{Path: "installation/token"}),
		revocationClient: &http.Client{
			Timeout:   reqTimeout,
			Transport: transport,
		},
		baseURL:          baseURL,
		installationsURL: installationsURL,
		installationsClient: &http.Client{
			Timeout:   reqTimeout,
			Transport: authenticatedTransport,
		},
		accessTokenURLTemplate: fmt.Sprintf(
			"%s/%%v/access_tokens",
			strings.TrimSuffix(installationsURL.String(), "/"),
		),
	}, nil
}

type tokenRequest struct {
	// OrgName is the organization name of where the GitHub app is installed.
	//
	// NOTE: OrgName is not actually part of the GitHub access tokens API[1]
	// payload. If set, we use it to indirectly lookup a real installation ID.
	//
	// [1]: https://git.io/JsQ7n
	OrgName string `json:"org_name"`

	// tokenRequest embeds tokenConstraints.
	tokenConstraints

	// InstallationID is the installation identifier of the GitHub App.
	InstallationID int `json:"installation_id"`

	// SkipInaccessibleRepositories makes the plugin tolerate repositories that
	// GitHub rejects as nonexistent or not accessible to the installation. It
	// is set per permission set and is not part of the GitHub API payload.
	SkipInaccessibleRepositories bool `json:"skip_inaccessible_repositories"`
}

// tokenConstraints allows for constraining the access scope of a token to
// specific repositories and permissions.
type tokenConstraints struct {
	// Permissions are the permissions granted to the access token, including
	// their access type.
	Permissions map[string]string `json:"permissions,omitempty"`
	// RepositoryIDs are the repository IDs that the token can access.
	RepositoryIDs []int `json:"repository_ids,omitempty"`
	// Repositories are the repository names that the token can access.
	Repositories []string `json:"repositories,omitempty"`
}

// statusCode models an HTTP response code.
type statusCode int

// Successful is true if the HTTP response code was between 200 and 300.
func (s statusCode) Successful() bool { return s >= 200 && s < 300 }

// Unsuccessful is true if the HTTP response code was not between 200 and 300.
func (s statusCode) Unsuccessful() bool { return !s.Successful() }

// Revoked is true if the HTTP response code was between 200 and 300, or was a
// 401 (Bad credentials).
func (s statusCode) Revoked() bool { return s.Successful() || s == 401 }

// Token returns a valid access token. If there are any failures on the wire or
// parsing request and response object, an error is returned.
func (c *Client) Token(ctx context.Context, tokReq *tokenRequest) (*logical.Response, error) {
	if tokReq == nil {
		return nil, errMissingTokenReq
	}

	// If installation ID is the default value, look up installation ID by
	// organization name first.
	if tokReq.InstallationID == 0 {
		var err error
		if tokReq.InstallationID, err = c.installationID(ctx, tokReq.OrgName); err != nil {
			return nil, err
		}
	}

	return c.token(ctx, tokReq)
}

// token requests an access token. If the request has SkipInaccessibleRepositories set
// and GitHub rejects a repository-constrained request with a 422 saying a
// repository is not accessible, it probes the requested repositories, drops
// those the App cannot reach and retries with the remainder. Any failure to do so returns the original error.
func (c *Client) token(ctx context.Context, tokReq *tokenRequest) (*logical.Response, error) {
	res, status, err := c.mint(ctx, tokReq)
	if err == nil ||
		status != http.StatusUnprocessableEntity ||
		!strings.Contains(err.Error(), inaccessibleRepositoryMessage) ||
		!tokReq.SkipInaccessibleRepositories ||
		len(tokReq.Repositories) == 0 {
		return res, err
	}

	kept, skipped, probeErr := c.accessibleRepositories(ctx, tokReq)
	if probeErr != nil || len(skipped) == 0 {
		return nil, err
	}

	if len(kept) == 0 {
		return nil, fmt.Errorf("%w: %s", err, errNoAccessibleRepositories)
	}

	// Retry on a copy so the caller's request (e.g. a stored permission set)
	// is not modified.
	retry := *tokReq
	retry.Repositories = kept

	res, _, err = c.mint(ctx, &retry)
	if err != nil {
		return nil, err
	}

	res.Data["skipped_repositories"] = skipped

	return res, nil
}

// mint performs a single access token request. The returned status is the HTTP
// status code of the response, or zero if no response was received.
func (c *Client) mint( //nolint:cyclop,funlen
	ctx context.Context,
	tokReq *tokenRequest,
) (*logical.Response, int, error) {
	accessTokenURL, err := c.accessTokenURLForInstallationID(tokReq.InstallationID)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", errUnableToBuildAccessTokenURL, err)
	}

	// Marshal a request body of token constraints, if any.
	body := new(bytes.Buffer)
	if err = json.NewEncoder(body).Encode(tokReq.tokenConstraints); err != nil {
		return nil, 0, err
	}

	// Build the token HTTP request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, accessTokenURL.String(), body)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", errUnableToBuildAccessTokenReq, err)
	}

	req.Header.Set("User-Agent", projectName)

	if body.Len() > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	// Perform the request, re-using the shared transport.
	res, err := c.installationsClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", errUnableToCreateAccessToken, err)
	}

	defer res.Body.Close() //nolint:errcheck

	if statusCode(res.StatusCode).Unsuccessful() {
		var bodyBytes []byte

		if bodyBytes, err = io.ReadAll(res.Body); err != nil {
			return nil, res.StatusCode, fmt.Errorf("%s: %w", errUnableToCreateAccessToken, err)
		}

		bodyErr := fmt.Errorf("%s: %s", res.Status, string(bodyBytes))

		return nil, res.StatusCode, fmt.Errorf("%s: %w", errUnableToCreateAccessToken, bodyErr)
	}

	var resData map[string]any
	if err = json.NewDecoder(res.Body).Decode(&resData); err != nil {
		return nil, res.StatusCode, fmt.Errorf("%w: %v", errUnableToDecodeAccessTokenRes, err)
	}

	// If excluding repository metadata, reduce memory consumption by trimming
	// it to a simple list of repository names.
	if c.ExcludeRepositoryMetadata {
		if repositoriesKey, ok := resData["repositories"]; ok {
			var (
				repos     = repositoriesKey.([]any)
				repoNames = make([]any, 0, len(repos))
			)

			for _, repo := range repos {
				repoNames = append(repoNames, repo.(map[string]any)["name"])
			}

			resData["repositories"] = repoNames
		}
	}

	if hashedToken, ok := hashedTokenFromValue(resData["token"]); ok {
		resData["hashed_token"] = hashedToken
	}

	// Enrich the response with what we know about the installation.
	tokRes := &logical.Response{Data: resData}
	tokRes.Data["installation_id"] = tokReq.InstallationID

	if tokReq.OrgName != "" {
		tokRes.Data["org_name"] = tokReq.OrgName
	}

	// As per the issue request in https://git.io/JUhRk, return a Vault "lease"
	// aligned to the GitHub token's `expires_at` field.
	if expiresAt, ok := resData["expires_at"]; ok {
		var expiresAtStr string

		if expiresAtStr, ok = expiresAt.(string); ok {
			var expiresAtTime time.Time

			if expiresAtTime, err = time.Parse(time.RFC3339, expiresAtStr); err == nil {
				tokRes.Secret = &logical.Secret{
					InternalData: map[string]any{"secret_type": backendSecretType},
					LeaseOptions: logical.LeaseOptions{
						TTL: time.Until(expiresAtTime),
					},
				}
			}
		}
	}

	return tokRes, res.StatusCode, nil
}

func (c *Client) accessTokenURLForInstallationID(installationID int) (*url.URL, error) {
	return url.ParseRequestURI(fmt.Sprintf(c.accessTokenURLTemplate, installationID))
}

func hashedTokenFromValue(token any) (string, bool) {
	tokenStr, ok := token.(string)
	if !ok || tokenStr == "" {
		return "", false
	}

	hash := sha256.Sum256([]byte(tokenStr))

	return base64.StdEncoding.EncodeToString(hash[:]), true
}

// ListInstallations retrieves a list of App installations associated with the
// client. It returns a logical.Response containing a map where the keys are
// account names and the values are corresponding installation IDs. In case of
// an error during the fetch operation, it returns nil and the error.
func (c *Client) ListInstallations(ctx context.Context) (*logical.Response, error) {
	instResult, err := c.fetchInstallations(ctx)
	if err != nil {
		return nil, err
	}

	installations := make(map[string]any, len(instResult))
	for _, v := range instResult {
		installations[v.Account.Login] = v.ID
	}

	return &logical.Response{Data: installations}, nil
}

// installationID makes a round trip to the configured GitHub API in an attempt
// to get the installation ID of the App.
func (c *Client) installationID(ctx context.Context, orgName string) (int, error) {
	instResult, err := c.fetchInstallations(ctx)
	if err != nil {
		return 0, err
	}

	for _, v := range instResult {
		if strings.EqualFold(v.Account.Login, orgName) {
			return v.ID, nil
		}
	}

	return 0, errAppNotInstalled
}

// fetchInstallations makes a request to the GitHub API to fetch the installations.
func (c *Client) fetchInstallations(ctx context.Context) ([]installation, error) {
	var allInstallations []installation

	url := c.installationsURL.String()
	for url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("User-Agent", projectName)

		// Perform the request, re-using the client's shared transport.
		res, err := c.installationsClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", errUnableToGetInstallations, err)
		}

		defer res.Body.Close() //nolint:errcheck

		if statusCode(res.StatusCode).Unsuccessful() {
			var bodyBytes []byte

			if bodyBytes, err = io.ReadAll(res.Body); err != nil {
				return nil, fmt.Errorf("%s: %w", errUnableToGetInstallations, err)
			}

			bodyErr := fmt.Errorf("%s: %s", res.Status, string(bodyBytes))

			return nil, fmt.Errorf("%s: %w", errUnableToGetInstallations, bodyErr)
		}

		var instResult []installation
		if err = json.NewDecoder(res.Body).Decode(&instResult); err != nil {
			return nil, fmt.Errorf("%s: %w", errUnableToDecodeInstallationsRes, err)
		}

		allInstallations = append(allInstallations, instResult...)

		// Check for pagination
		url = getNextPageURL(res.Header.Get("Link"))
	}

	return allInstallations, nil
}

// getNextPageURL parses the Link header to find the URL for the next page.
func getNextPageURL(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}

	links := strings.Split(linkHeader, ",")
	for _, link := range links {
		parts := strings.Split(strings.TrimSpace(link), ";")
		if len(parts) < 2 {
			continue
		}

		urlPart := strings.Trim(parts[0], "<>")
		relPart := strings.TrimSpace(parts[1])

		if relPart == `rel="next"` {
			return urlPart
		}
	}

	return ""
}

// Model the parts of a installations list response that we care about.
type (
	account struct {
		Login string `json:"login"`
	}
	installation struct {
		Account account `json:"account"`
		ID      int     `json:"id"`
	}
)

// repositoryProbeConcurrency bounds the number of concurrent repository probes.
const repositoryProbeConcurrency = 8

// accessibleRepositories splits the requested repositories into those the App
// is installed on and those it is not. A repository is skipped only when GitHub
// answers 404 for it; any other response aborts the probe with an error so that
// callers fall back to the original token request error.
func (c *Client) accessibleRepositories(
	ctx context.Context,
	tokReq *tokenRequest,
) (kept, skipped []string, err error) {
	org, err := c.installationOrg(ctx, tokReq)
	if err != nil {
		return nil, nil, err
	}

	var (
		accessible = make([]bool, len(tokReq.Repositories))
		errs       = make([]error, len(tokReq.Repositories))
		sem        = make(chan struct{}, repositoryProbeConcurrency)
		wg         sync.WaitGroup
	)

	for i, repo := range tokReq.Repositories {
		wg.Add(1)

		sem <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			accessible[i], errs[i] = c.repositoryInstalled(ctx, org, repo)
		}()
	}

	wg.Wait()

	for i, repo := range tokReq.Repositories {
		switch {
		case errs[i] != nil:
			return nil, nil, errs[i]
		case accessible[i]:
			kept = append(kept, repo)
		default:
			skipped = append(skipped, repo)
		}
	}

	return kept, skipped, nil
}

// installationOrg returns the organization name for the token request,
// resolving it from the installation ID when it was not provided.
func (c *Client) installationOrg(ctx context.Context, tokReq *tokenRequest) (string, error) {
	if tokReq.OrgName != "" {
		return tokReq.OrgName, nil
	}

	installations, err := c.fetchInstallations(ctx)
	if err != nil {
		return "", err
	}

	for _, v := range installations {
		if v.ID == tokReq.InstallationID {
			return v.Account.Login, nil
		}
	}

	return "", errInstallationNotFound
}

// repositoryInstalled reports whether the App is installed on the repository,
// using the App-authenticated repository installation endpoint.
func (c *Client) repositoryInstalled(ctx context.Context, org, repo string) (bool, error) {
	key := org + "/" + repo

	if expiry, ok := c.uninstalledRepos.Load(key); ok {
		if time.Now().Before(expiry.(time.Time)) { //nolint:forcetypeassert
			return false, nil
		}

		c.uninstalledRepos.Delete(key)
	}

	u := c.baseURL.JoinPath("repos", org, repo, "installation")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, fmt.Errorf("%s: %w", errUnableToProbeRepository, err)
	}

	req.Header.Set("User-Agent", projectName)

	res, err := c.installationsClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("%s: %w", errUnableToProbeRepository, err)
	}

	defer res.Body.Close() //nolint:errcheck

	switch {
	case statusCode(res.StatusCode).Successful():
		return true, nil
	case res.StatusCode == http.StatusNotFound:
		c.uninstalledRepos.Store(key, time.Now().Add(uninstalledRepositoryTTL))

		return false, nil
	default:
		return false, fmt.Errorf("%s: %s", errUnableToProbeRepository, res.Status)
	}
}

// RevokeToken takes a valid access token and performs a revocation against
// GitHub's APIs. If there are any failures on the wire or parsing request
// and response object, an error is returned.
func (c *Client) RevokeToken(ctx context.Context, token string) (*logical.Response, error) {
	// Build the revocation request.
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.revocationURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errUnableToBuildAccessTokenRevReq, err)
	}

	req.Header.Set("User-Agent", projectName)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// Perform the request, re-using the shared transport.
	res, err := c.revocationClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errUnableToRevokeAccessToken, err)
	}

	defer res.Body.Close() //nolint:errcheck

	if !statusCode(res.StatusCode).Revoked() {
		var bodyBytes []byte

		if bodyBytes, err = io.ReadAll(res.Body); err != nil {
			return nil, fmt.Errorf("%s: %w", errUnableToRevokeAccessToken, err)
		}

		bodyErr := fmt.Errorf("%s: %s", res.Status, string(bodyBytes))

		return nil, fmt.Errorf("%s: %w", errUnableToRevokeAccessToken, bodyErr)
	}

	return &logical.Response{}, nil
}
