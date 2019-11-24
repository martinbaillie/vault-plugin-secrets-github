package github

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Linker-provided project/build information.
var (
	projectName    string
	projectDocs    string
	projectVersion string
	buildTime      string
	buildCommit    string
	buildLink      string
)

const pathPatternInfo = "info"

const pathInfoHelpSyn = `
Display information about the GitHub secrets plugin.
`

const pathInfoHelpDesc = `
Display information about the GitHub secrets plugin, such as the plugin version,
VCS detail and where to get help.
`

func (b *backend) pathInfo() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternInfo,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathInfoRead,
			},
		},
		HelpSynopsis:    pathInfoHelpSyn,
		HelpDescription: pathInfoHelpDesc,
	}
}

func (b *backend) pathInfoRead(
	_ context.Context,
	_ *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"project_name":    projectName,
			"project_version": projectVersion,
			"project_docs":    projectDocs,
			"build_commit":    buildCommit,
			"build_time":      buildTime,
			"build_link":      buildLink,
		},
	}, nil
}
