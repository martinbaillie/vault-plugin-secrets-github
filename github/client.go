package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	errBody                           = errors.New("error body")
	errClientConfigNil                = errors.New("client configuration was nil")
	errMissingTokenReq                = errors.New("missing access token request")
	errUnableToBuildAccessTokenReq    = errors.New("unable to build access token request")
	errUnableToBuildAccessTokenRevReq = errors.New("unable to build access token revocation request")
	errUnableToBuildAccessTokenURL    = errors.New("unable to build access token URL")
	errUnableToCreateAccessToken      = errors.New("unable to create access token")
	errUnableToDecodeAccessTokenRes   = errors.New("unable to decode access token response")
	errUnableToDecodeInstallationsRes = errors.New("unable to decode installations list response")
	errUnableToGetInstallations       = errors.New("unable to get installations")
	errUnableToRevokeAccessToken      = errors.New("unable to revoke access token")
	errAppNotInstalled                = errors.New("app not installed in GitHub organization")
)

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
}

// NewClient returns a newly constructed client from the provided config and
// with sensible default transport settings. It will error if it fails to
// validate necessary configuration formats like URIs and PEM encoded private
// keys.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, errClientConfigNil
	}

	// A sensible request timeout. We could make this configurable in future.
	reqTimeout := time.Millisecond * 5000

	// Initialise a new transport instead of using Go's default. This transport
	// has explicit timeouts and sensible defaults for max connections per host
	// (i.e. their zero values—unlimited).
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: reqTimeout / 2,
		}).DialContext,
		TLSHandshakeTimeout: reqTimeout / 2,
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
		return nil, fmt.Errorf("parsing base URL: %w", err)
	}

	installationsURL := baseURL.ResolveReference(&url.URL{Path: "app/installations"})

	return &Client{
		revocationURL: baseURL.ResolveReference(&url.URL{Path: "installation/token"}),
		revocationClient: &http.Client{
			Timeout:   reqTimeout,
			Transport: transport,
		},
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
	OrgName string `json:"-"`

	// tokenRequest embeds tokenConstraints.
	tokenConstraints

	// InstallationID is the installation identifier of the GitHub App.
	InstallationID int `json:"installation_id"`
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

	// If installation ID is nil, presume we are looking up installation ID by
	// organization name first.
	if tokReq.InstallationID == 0 {
		var err error
		if tokReq.InstallationID, err = c.installationID(ctx, tokReq.OrgName); err != nil {
			return nil, err
		}
	}

	return c.token(ctx, tokReq)
}

func (c *Client) token(ctx context.Context, tokReq *tokenRequest) (*logical.Response, error) {
	accessTokenURL, err := c.accessTokenURLForInstallationID(tokReq.InstallationID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnableToBuildAccessTokenURL, err)
	}

	// Marshal a request body of token constraints, if any.
	body := new(bytes.Buffer)
	if err = json.NewEncoder(body).Encode(tokReq.tokenConstraints); err != nil {
		return nil, err
	}

	// Build the token HTTP request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, accessTokenURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnableToBuildAccessTokenReq, err)
	}

	req.Header.Set("User-Agent", projectName)

	if body.Len() > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	// Perform the request, re-using the shared transport.
	res, err := c.installationsClient.Do(req)
	// res, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("%w: RoundTrip error: %v", errUnableToCreateAccessToken, err)
	}

	defer res.Body.Close()

	if statusCode(res.StatusCode).Unsuccessful() {
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: error reading error response body: %v",
				errUnableToCreateAccessToken, res.Status, err)
		}

		bodyErr := fmt.Errorf("%w: %v", errBody, string(bodyBytes))

		return nil, fmt.Errorf("%w: %s: %v", errUnableToCreateAccessToken,
			res.Status, bodyErr)
	}

	var resData map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&resData); err != nil {
		return nil, fmt.Errorf("%w: %v", errUnableToDecodeAccessTokenRes, err)
	}

	tokRes := &logical.Response{Data: resData}

	// Enrich the response with what we know about the installation.
	tokRes.Data["installation_id"] = tokReq.InstallationID
	if tokReq.OrgName != "" {
		tokRes.Data["org_name"] = tokReq.OrgName
	}

	// As per the issue request in https://git.io/JUhRk, return a Vault "lease"
	// aligned to the GitHub token's `expires_at` field.
	if expiresAt, ok := resData["expires_at"]; ok {
		if expiresAtStr, ok := expiresAt.(string); ok {
			if expiresAtTime, err := time.Parse(time.RFC3339, expiresAtStr); err == nil {
				tokRes.Secret = &logical.Secret{
					InternalData: map[string]interface{}{"secret_type": backendSecretType},
					LeaseOptions: logical.LeaseOptions{
						TTL: time.Until(expiresAtTime),
					},
				}
			}
		}
	}

	return tokRes, nil
}

func (c *Client) accessTokenURLForInstallationID(installationID int) (*url.URL, error) {
	return url.ParseRequestURI(fmt.Sprintf(c.accessTokenURLTemplate, installationID))
}

// installationID makes a round trip to the configured GitHub API in an attempt to get the
// installation ID of the App.
func (c *Client) installationID(ctx context.Context, orgName string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.installationsURL.String(), nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("User-Agent", projectName)

	// Perform the request, re-using the client's shared transport.
	res, err := c.installationsClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: RoundTrip error: %v", errUnableToGetInstallations, err)
	}

	defer res.Body.Close()

	if statusCode(res.StatusCode).Unsuccessful() {
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return 0, fmt.Errorf("%w: %s: error reading error response body: %v",
				errUnableToGetInstallations, res.Status, err)
		}

		bodyErr := fmt.Errorf("%w: %v", errBody, string(bodyBytes))

		return 0, fmt.Errorf("%w: %s: %v", errUnableToGetInstallations,
			res.Status, bodyErr)
	}

	var instResult []installation
	if err := json.NewDecoder(res.Body).Decode(&instResult); err != nil {
		return 0, fmt.Errorf("%w: %v", errUnableToDecodeInstallationsRes, err)
	}

	for _, v := range instResult {
		if v.Account.Login == orgName {
			return v.ID, nil
		}
	}

	return 0, errAppNotInstalled
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

// RevokeToken takes a valid access token and performs a revocation against
// GitHub's APIs. If there are any failures on the wire or parsing request
// and response object, an error is returned.
func (c *Client) RevokeToken(ctx context.Context, token string) (*logical.Response, error) {
	// Build the revocation request.
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.revocationURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnableToBuildAccessTokenRevReq, err)
	}

	req.Header.Set("User-Agent", projectName)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// Perform the request, re-using the shared transport.
	res, err := c.revocationClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: RoundTrip error: %v", errUnableToRevokeAccessToken, err)
	}

	defer res.Body.Close()

	if !statusCode(res.StatusCode).Revoked() {
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: error reading error response body: %v",
				errUnableToRevokeAccessToken, res.Status, err)
		}

		bodyErr := fmt.Errorf("%w: %v", errBody, string(bodyBytes))

		return nil, fmt.Errorf("%w: %s: %v", errUnableToRevokeAccessToken,
			res.Status, bodyErr)
	}

	return &logical.Response{}, nil
}
