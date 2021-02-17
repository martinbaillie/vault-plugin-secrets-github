package github

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	permissionsetStoragePrefix = "permissionset"

	pathPermissionSetHelpSyn  = `Read/write GitHub permission sets for Github access tokens.`
	pathPermissionSetHelpDesc = `
This path allows you create permission sets, which bind sets of permissions
to specific GitHub access token. Secrets (access tokens) are generated
under a permission set and will have the given set of permission on GitHub.
The specified binding file accepts JSON string with the following format:
{
	"repository_ids": [
		123,
		456,
		789,
		...
	]
	"permissions": {
		"pull_requests": "read",
		"contents": "read",
		...
	}
}
`
	pathListPermissionSetHelpSyn  = `List existing permission sets.`
	pathListPermissionSetHelpDesc = `List created permission sets.`
)

var (
	errPermissionSetNameEmpty        = errors.New("permission set name is empty")
	errPermissionSetTokenOptionEmpty = errors.New("permission set option is empty")
)

type PermissionSet struct {
	Name string

	TokenOptions *tokenOptions
}

func (ps *PermissionSet) validate() error {
	if ps.Name == "" {
		return errPermissionSetNameEmpty
	}
	if ps.TokenOptions == nil {
		return errPermissionSetTokenOptionEmpty
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

func (b *backend) pathPermissionSet() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("permissionset/%s", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Required. Name of the permission set.",
			},
			keyRepoIDs: {
				Type:        framework.TypeCommaIntSlice,
				Description: descRepoIDs,
			},
			keyPerms: {
				Type:        framework.TypeKVPairs,
				Description: descPerms,
			},
		},
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

func (b *backend) pathPermissionSetList() *framework.Path {
	// Paths for listing permission sets
	return &framework.Path{
		Pattern: "permissionsets?/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathPermissionSetListRead,
			},
		},
		HelpSynopsis:    pathListPermissionSetHelpSyn,
		HelpDescription: pathListPermissionSetHelpDesc,
	}
}

func (b *backend) pathPermissionSetRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw := d.Get("name")

	ps, err := getPermissionSet(nameRaw.(string), ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if ps == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		keyRepoIDs: ps.TokenOptions.RepositoryIDs,
		keyPerms:   ps.TokenOptions.Permissions,
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathPermissionSetDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw := d.Get("name")
	psName := nameRaw.(string)

	_, err := getPermissionSet(psName, ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("unable to get permission set %s: %w", psName, err)
	}

	b.permissionsetLock.Lock()
	defer b.permissionsetLock.Unlock()

	if err := req.Storage.Delete(ctx, fmt.Sprintf("permissionset/%s", nameRaw)); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathPermissionSetCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw := d.Get("name")
	name := nameRaw.(string)

	ps, err := getPermissionSet(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if ps == nil {
		ps = &PermissionSet{
			Name:         name,
			TokenOptions: new(tokenOptions),
		}
	}

	if perms, ok := d.GetOk(keyPerms); ok {
		ps.TokenOptions.Permissions = perms.(map[string]string)
	}

	if repoIDs, ok := d.GetOk(keyRepoIDs); ok {
		ps.TokenOptions.RepositoryIDs = repoIDs.([]int)
	}

	// Save permissions set
	if err := ps.save(ctx, req.Storage); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return nil, nil
}

func (b *backend) pathPermissionSetListRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	permissionsets, err := req.Storage.List(ctx, "permissionset/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(permissionsets), nil
}
