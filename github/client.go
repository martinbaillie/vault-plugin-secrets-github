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

const (
	fmtErrUnableToBuildAccessTokenReq  = "unable to build access token request"
	fmtErrUnableToCreateAccessToken    = "unable to create access token"
	fmtErrUnableToDecodeAccessTokenRes = "unable to decode access token response"
)

var errClientConfigNil = errors.New("client configuration was nil")

// Client encapsulates an HTTP client for talking to the configured GitHub App.
type Client struct {
	*Config

	// URL is the access token URL for this client.
	url *url.URL

	// Transport is the HTTP transport used for this client.
	transport http.RoundTripper
}

// NewClient returns a newly constructed client from the provided config. It
// will error if it fails to validate necessary configuration formats like URIs
// and PEM encoded private keys.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, errClientConfigNil
	}

	transport, err := ghinstallation.NewAppsTransport(
		http.DefaultTransport,
		int64(config.AppID),
		[]byte(config.PrvKey),
	)
	if err != nil {
		return nil, err
	}

	url, err := url.ParseRequestURI(fmt.Sprintf(
		"%s/app/installations/%v/access_tokens",
		strings.TrimSuffix(fmt.Sprint(config.BaseURL), "/"),
		config.InsID,
	))
	if err != nil {
		return nil, err
	}

	return &Client{config, url, transport}, nil
}

// tokenOptions allows for constraining the access scope of a token to specific
// repositories and permissions.
type tokenOptions struct {
	// Permissions are the permissions granted to the access token, including
	// their access type.
	Permissions map[string]string `json:"permissions,omitempty"`
	// RepositoryIDs are the repository IDs that the token can access.
	RepositoryIDs []int `json:"repository_ids,omitempty"`
}

// statusCode models an HTTP response code.
type statusCode int

// Successful is true if the HTTP response code was between 200 and 300.
func (s statusCode) Successful() bool { return s >= 200 && s < 300 }

// Unsuccessful is true if the HTTP response code was not between 200 and 300.
func (s statusCode) Unsuccessful() bool { return !s.Successful() }

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

	// Build the token request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url.String(), body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fmtErrUnableToBuildAccessTokenReq, err)
	}

	req.Header.Set("User-Agent", projectName)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Perform the request, re-using the shared transport.
	res, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("%s: RoundTrip error: %w", fmtErrUnableToCreateAccessToken, err)
	}

	defer res.Body.Close()

	if statusCode(res.StatusCode).Unsuccessful() {
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: error reading error response body: %s", fmtErrUnableToCreateAccessToken, res.Status, err)
		}
		bodyString := string(bodyBytes)

		return nil, fmt.Errorf("%s: %s: error body: %s", fmtErrUnableToCreateAccessToken, res.Status, bodyString)
	}

	var resData map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&resData); err != nil {
		return nil, fmt.Errorf("%s: %w", fmtErrUnableToDecodeAccessTokenRes, err)
	}

	tokenRes := &logical.Response{Data: resData}

	// As per the issue request in https://git.io/JUhRk, return a Vault "lease"
	// aligned to the GitHub token's `expires_at` field.
	if expiresAt, ok := resData["expires_at"]; ok {
		if expiresAtStr, ok := expiresAt.(string); ok {
			if expiresAtTime, err := time.Parse(time.RFC3339, expiresAtStr); err == nil {
				tokenRes.Secret = &logical.Secret{
					LeaseOptions: logical.LeaseOptions{
						TTL: time.Until(expiresAtTime),
					},
				}
			}
		}
	}

	return tokenRes, nil
}
