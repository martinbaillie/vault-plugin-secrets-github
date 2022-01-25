package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	errUnableToBuildAccessTokenURL    = errors.New("unable to build access token URL")
	errUnableToBuildAccessTokenReq    = errors.New("unable to build access token request")
	errUnableToBuildAccessTokenRevReq = errors.New("unable to build access token revocation request")
	errUnableToCreateAccessToken      = errors.New("unable to create access token")
	errUnableToRevokeAccessToken      = errors.New("unable to revoke access token")
	errUnableToDecodeAccessTokenRes   = errors.New("unable to decode access token response")
	errBody                           = errors.New("error body")
	errClientConfigNil                = errors.New("client configuration was nil")
)

// Client encapsulates an HTTP client for talking to the configured GitHub App.
type Client struct {
	*Config

	// URL is the access token URL template for this client.
	accessTokenURLTemplate string

	// Transport is the HTTP transport used for token requests.
	transport http.RoundTripper

	// RevocationURL is the access token revocation URL for this client.
	revocationURL *url.URL

	// RevocationTransport is the HTTP transport used for revocation requests.
	revocationTransport http.RoundTripper
}

// NewClient returns a newly constructed client from the provided config. It
// will error if it fails to validate necessary configuration formats like URIs
// and PEM encoded private keys.
func NewClient(config *Config) (c *Client, err error) {
	if config == nil {
		return nil, errClientConfigNil
	}

	c = &Client{
		revocationTransport: http.DefaultTransport,
	}

	if c.transport, err = ghinstallation.NewAppsTransport(
		http.DefaultTransport,
		int64(config.AppID),
		[]byte(config.PrvKey),
	); err != nil {
		return nil, err
	}

	c.accessTokenURLTemplate = fmt.Sprintf(
		"%s/app/installations/%%v/access_tokens",
		strings.TrimSuffix(fmt.Sprint(config.BaseURL), "/"),
	)

	if c.revocationURL, err = url.ParseRequestURI(fmt.Sprintf(
		"%s/installation/token",
		strings.TrimSuffix(fmt.Sprint(config.BaseURL), "/"),
	)); err != nil {
		return nil, err
	}

	return c, nil
}

// tokenOptions allows for constraining the access scope of a token to specific
// repositories and permissions.
type tokenOptions struct {
	// Permissions are the permissions granted to the access token, including
	// their access type.
	Permissions map[string]string `json:"permissions,omitempty"`
	// InstallationID is the installation ID  that the token can access.
	InstallationID int `json:"installation_id"`
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

// Revoked is true if the HTTP response code was between 200 and 300, or was a 401 (Bad credentials).
func (s statusCode) Revoked() bool { return s.Successful() || s == 401 }

// Token returns a valid access token. If there are any failures on the wire or
// parsing request and response object, an error is returned.
func (c *Client) Token(ctx context.Context, opts *tokenOptions) (*logical.Response, error) {
	// Marshal a request body only if there are any user-specified GitHub App
	// token constraints.
	var body io.ReadWriter
	if opts != nil {
		body = new(bytes.Buffer)
		if err := json.NewEncoder(body).Encode(opts); err != nil {
			return nil, err
		}
	}

	accessTokenURL, err := c.getAccessTokenURLForInstallationID(opts.InstallationID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnableToBuildAccessTokenURL, err)
	}

	// Build the token request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, accessTokenURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnableToBuildAccessTokenReq, err)
	}

	req.Header.Set("User-Agent", projectName)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Perform the request, re-using the shared transport.
	res, err := c.transport.RoundTrip(req)
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

	tokenRes := &logical.Response{Data: resData}

	// As per the issue request in https://git.io/JUhRk, return a Vault "lease"
	// aligned to the GitHub token's `expires_at` field.
	if expiresAt, ok := resData["expires_at"]; ok {
		if expiresAtStr, ok := expiresAt.(string); ok {
			if expiresAtTime, err := time.Parse(time.RFC3339, expiresAtStr); err == nil {
				tokenRes.Secret = &logical.Secret{
					InternalData: map[string]interface{}{"secret_type": backendSecretType},
					LeaseOptions: logical.LeaseOptions{
						TTL: time.Until(expiresAtTime),
					},
				}
			}
		}
	}

	return tokenRes, nil
}

func (c *Client) getAccessTokenURLForInstallationID(installationID int) (*url.URL, error) {
	return url.ParseRequestURI(fmt.Sprintf(
		c.accessTokenURLTemplate,
		installationID,
	))
}

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
	res, err := c.revocationTransport.RoundTrip(req)
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
