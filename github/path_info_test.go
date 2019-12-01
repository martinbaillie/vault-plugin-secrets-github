package github

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/prometheus/common/version"
	"gotest.tools/assert"
)

func TestBackend_PathInfoRead(t *testing.T) {
	t.Parallel()

	testInfo := map[string]string{
		"project_name":   "testProjectName",
		"project_docs":   "https://test.project.docs.com",
		"build_version":  "v1.0.0",
		"build_revision": "deadbee",
		"build_branch":   "master",
		"build_user":     "martin",
		"build_date":     time.Now().String(),
	}
	version.Version = testInfo["build_version"]
	version.Revision = testInfo["build_revision"]
	version.Branch = testInfo["build_branch"]
	version.BuildUser = testInfo["build_user"]
	version.BuildDate = testInfo["build_date"]
	projectName = testInfo["project_name"]
	projectDocs = testInfo["project_docs"]

	b, storage := testBackend(t)

	res, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      pathPatternInfo,
	})
	assert.NilError(t, err)

	resData := make(map[string]string)
	for k, v := range res.Data {
		resData[k] = v.(string)
	}
	assert.DeepEqual(t, resData, testInfo)
}
