package github

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	permissionsetStoragePrefix = "permissionset"
)

type PermissionSet struct {
	Name string

	TokenOptions *tokenOptions
}

func (ps *PermissionSet) validate() error {
	if ps.Name == "" {
		return errors.New("permission set name is empty")
	}
	return nil
}

func (ps *PermissionSet) save(ctx context.Context, s logical.Storage) error {
	if err := ps.validate(); err != nil {
		return err
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", permissionsetStoragePrefix, ps.Name), ps)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (b *backend) pathPermissionSet() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("permissionset/%s", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Required. Name of the permission set.",
			},
			"options": {
				Type:        framework.TypeString,
				Description: "Token options configuration string.",
			},
		},
		ExistenceCheck: b.pathPermissionSetExistenceCheck("name"),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathPermissionSetDelete,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathPermissionSetRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathPermissionSetCreateUpdate,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathPermissionSetCreateUpdate,
			},
		},
		HelpSynopsis:    pathPermissionSetHelpSyn,
		HelpDescription: pathPermissionSetHelpDesc,
	}
}

func pathPermissionSetList(b *backend) *framework.Path {
	// Paths for listing permission sets
	return &framework.Path{
		Pattern: "permissionsets?/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathPermissionSetList,
			},
		},
		HelpSynopsis:    pathListPermissionSetHelpSyn,
		HelpDescription: pathListPermissionSetHelpDesc,
	}
}

func (b *backend) pathPermissionSetExistenceCheck(permissionsetFieldName string) framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
		// check for either name or permissionset
		nameRaw, ok := d.GetOk(permissionsetFieldName)
		if !ok {
			return false, errors.New("permissionset name is required")
		}

		ps, err := getPermissionSet(nameRaw.(string), ctx, req.Storage)
		if err != nil {
			return false, err
		}

		return ps != nil, nil
	}
}

func (b *backend) pathPermissionSetRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	ps, err := getPermissionSet(nameRaw.(string), ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if ps == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"options": ps.TokenOptions,
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathPermissionSetDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	psName := nameRaw.(string)

	ps, err := getPermissionSet(psName, ctx, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("unable to get permission set %s: {{err}}", psName), err)
	}
	if ps == nil {
		return nil, nil
	}

	b.permissionsetLock.Lock()
	defer b.permissionsetLock.Unlock()

	if err := req.Storage.Delete(ctx, fmt.Sprintf("permissionset/%s", nameRaw)); err != nil {
		return nil, err
	}

	// Clean up resources:
	return nil, nil
}

func (b *backend) pathPermissionSetCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//var warnings []string
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	ps, err := getPermissionSet(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if ps == nil {
		ps = &PermissionSet{
			Name: name,
		}
	}

	isCreate := req.Operation == logical.CreateOperation
	// Bindings
	bRaw, newTokenOptions := d.GetOk("options")

	if newTokenOptions {
		tokenopts, ok := bRaw.(string)
		if !ok {
			return logical.ErrorResponse("tokenOptions are not a string"), nil
		}
		if tokenopts == "" {
			return logical.ErrorResponse("tokenOptions are empty"), nil
		}
	}

	if isCreate && !newTokenOptions {
		return logical.ErrorResponse("tokenOption are required for new permission set"), nil
	}

	//Save permissions set
	if err := ps.save(ctx, req.Storage); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return nil, nil
}

func (b *backend) pathPermissionSetList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	permissionsets, err := req.Storage.List(ctx, "permissionset/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(permissionsets), nil
}

func getPermissionSet(name string, ctx context.Context, s logical.Storage) (*PermissionSet, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", permissionsetStoragePrefix, name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	ps := &PermissionSet{}
	if err := entry.DecodeJSON(ps); err != nil {
		return nil, err
	}
	return ps, nil
}

const pathPermissionSetHelpSyn = `Read/write GitHub permission sets for tokens.`
const pathPermissionSetHelpDesc = `
TODO
`

const pathListPermissionSetHelpSyn = `List existing permission sets.`
const pathListPermissionSetHelpDesc = `List created permission sets.`
