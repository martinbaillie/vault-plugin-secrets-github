package github

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/assert"
)

// testFieldValidation is a helper that verifies the operation on the given path
// has field validation.
func testFieldValidation(t *testing.T, o logical.Operation, p string) {
	t.Helper()

	b, storage := testBackend(t)
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: o,
		Path:      p,
		Data: map[string]interface{}{
			"nonexistent": true,
		},
	})

	assert.ErrorContains(t, err, "unknown field")
}

func TestPathValidateFields(t *testing.T) {
	t.Parallel()

	testFieldData := &framework.FieldData{
		Schema: map[string]*framework.FieldSchema{
			"testInt":    {Type: framework.TypeInt},
			"testString": {Type: framework.TypeString},
			"testMap":    {Type: framework.TypeMap},
		},
	}

	cases := []struct {
		name string
		data map[string]interface{}
		err  error
	}{
		{
			name: "HappyPath",
			data: map[string]interface{}{
				"testInt":    1985,
				"testString": "Scotland",
			},
		},
		{
			name: "Empty",
			data: map[string]interface{}{},
		},
		{
			name: "UnknownField",
			data: map[string]interface{}{
				"unknownField": 1989,
			},
			err: errors.New(fmtErrUnknownField),
		},
		{
			name: "UnknownFields",
			data: map[string]interface{}{
				"testInt":       1985,
				"testString":    "Scotland",
				"unknownField1": "",
				"unknownField2": 0.09,
			},
			err: errors.New(fmtErrUnknownFields),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateFields(&logical.Request{Data: tc.data}, testFieldData)

			if tc.err != nil {
				assert.ErrorContains(t, err, tc.err.Error())
			} else {
				assert.NilError(t, err)
			}
		})
	}
}
