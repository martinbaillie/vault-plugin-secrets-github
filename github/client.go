package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/bradleyfalzon/ghinstallation"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	fmtErrUnableToBuildAccessTokenReq  = "unable to build access token request"
	fmtErrUnableToCreateAccessToken    = "unable to create access token"
	fmtErrUnableToDecodeAccessTokenRes = "unable to decode access token response"
)

var errClientConfigNil = errors.New("client configuration was nil")

type Client struct {
	*Config

	// URL is the access token URL for this client.
	url *url.URL

	// Transport is the HTTP transport used for this client.
	transport http.RoundTripper
}

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

// statusCode models an HTTP response code.
type statusCode int

// Successful is true if the HTTP response code was between 200 and 300.
func (s statusCode) Successful() bool { return s >= 200 && s < 300 }

// Unsuccessful is true if the HTTP response code was not between 200 and 300.
func (s statusCode) Unsuccessful() bool { return !s.Successful() }

// TODO(mbaillie): reduce cyclomatic complexity
func (c *Client) Token(
	ctx context.Context,
	reqData *framework.FieldData,
) (*logical.Response, error) {
	// Marshal a request body only if there are any user-specified GitHub App
	// token constraints.
	var body io.ReadWriter
	if reqData != nil {
		body = new(bytes.Buffer)
		if err := json.NewEncoder(body).Encode(reqData.Raw); err != nil {
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
		return nil, fmt.Errorf("%s: %w", fmtErrUnableToCreateAccessToken, err)
	}

	defer res.Body.Close()

	if statusCode(res.StatusCode).Unsuccessful() {
		return nil, fmt.Errorf("%s: %s", fmtErrUnableToCreateAccessToken, res.Status)
	}

	var resData map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&resData); err != nil {
		return nil, fmt.Errorf("%s: %w", fmtErrUnableToDecodeAccessTokenRes, err)
	}

	return &logical.Response{Data: resData}, nil
}
