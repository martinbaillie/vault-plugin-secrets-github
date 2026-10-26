package github

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	errUnknownField    = Error("unknown field")
	errUnknownFields   = Error("unknown fields")
	errEmptyConstraint = Error("cannot be empty")
)

// withFieldValidator wraps an OperationFunc and validates the user-supplied
// fields match the schema.
func withFieldValidator(f framework.OperationFunc) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		if err := validateFields(req, d); err != nil {
			return nil, logical.CodedError(400, err.Error())
		}

		return f(ctx, req, d)
	}
}

// validateFields verifies that no bad arguments were given to the request.
func validateFields(req *logical.Request, data *framework.FieldData) error {
	var unknownFields []string

	for k := range req.Data {
		if _, ok := data.Schema[k]; !ok {
			unknownFields = append(unknownFields, k)
		}
	}

	switch len(unknownFields) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("%w: %s", errUnknownField, unknownFields[0])
	default:
		sort.Strings(unknownFields)

		return fmt.Errorf("%w: %s", errUnknownFields, strings.Join(unknownFields, ", "))
	}
}

// setConstraints copies the token constraints sent in d to c. Constraints that
// are not sent are left as they are.
//
// It rejects constraints that are sent but empty. GitHub treats a missing
// constraint as no constraint, and the plugin drops empty constraints from its
// request to GitHub. An empty value would therefore mint a token with all of
// the installation's access. Vault policy 'allowed_parameters' accepts an empty
// list, so policy does not stop this.
func setConstraints(d *framework.FieldData, c *tokenConstraints) error {
	if v, ok := d.GetOk(keyPerms); ok {
		if c.Permissions = v.(map[string]string); len(c.Permissions) == 0 {
			return fmt.Errorf("%s %w", keyPerms, errEmptyConstraint)
		}
	}

	if v, ok := d.GetOk(keyRepoIDs); ok {
		if c.RepositoryIDs = v.([]int); len(c.RepositoryIDs) == 0 {
			return fmt.Errorf("%s %w", keyRepoIDs, errEmptyConstraint)
		}
	}

	if v, ok := d.GetOk(keyRepos); ok {
		if c.Repositories = v.([]string); len(c.Repositories) == 0 {
			return fmt.Errorf("%s %w", keyRepos, errEmptyConstraint)
		}
	}

	return nil
}
