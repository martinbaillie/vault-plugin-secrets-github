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
	errUnknownField  = Error("unknown field")
	errUnknownFields = Error("unknown fields")
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
