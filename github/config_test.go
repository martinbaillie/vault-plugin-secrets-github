package github

import (
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"

	"gotest.tools/assert"
)

const (
	testAppID1      = 45793
	testAppID2      = 45794
	testInsID1      = 5018415
	testInsID2      = 5018416
	testOrgName1    = "test-1"
	testOrgName2    = "test-2"
	testPrvKeyValid = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvPdtXHe2CjNgCZbjpPGT9tkOloOvEfrqQhW5uGq2vRepdMWE
rrV0CtcIk6kYRPfW9D8+XZfI7YBnW2uy/CqTUVWqVfnz70uOzurmOAeYOVzwQtHB
e4GXrdVZR2pKD1De2hO5o1QL09Er99EMxaD9mPFsWqj0ybrYYRPeT0b0kgmdwgu7
QRJjUW6Ynbb6GCYI3VcRkxaEE3Hd9BQhDyLpXAnyStM1h5hnxDsx5hGnbadWyII0
ztLQjFlNDkv/5gvaPTgyq7VI5lKy5nCoIuAhKfAMim6Wv6XkLO0eamXDSzleCAkV
A4X14fwFB1lTh07h/rITsqnLlzmSivov243lXwIDAQABAoIBAAIsjpOLxQplAOvb
Uo8pQFyMrsBIj5ETY/KSsWpPv/548TgotZgU+lrNkomwXlkcyNpSh/MnteYVnhrN
KGgCTWOYKreGgqn0IpZ62V83pyaxzQnXw/QZz5buZ3KM5IE8mvPDWlVouCIdu/XD
7/OuIHzL+kUowHg5sBed1ObwmAu+D4ASld+Hey0cz4Vo2am3jIYigSju/9P5rpg0
m0tzIzDHkTRVS2j/2mxROPSDMtx79bH7XyqP7bWwP5ohAIHLuBCmNDotAlrwS5/S
5uHwuUHapK5UnhSk0E1Ljzj6Uj1Y16OxodsW0wWvckiFZyVCTqzVWDUfAGbY8Yy/
hv05BsECgYEA7+71Brxeoam3KY4qF9zGzFi6l0ovqXboXk7JZ/IgquYb8xrNC99h
K4wOts8eYYQInJGFv2nowjqqMh1R6ALKPudf0QLNvXiQjmP/hViXoYLLWhQZcTqh
f3XIFrFG4lKZaFfbbUTB8c4hqjyhaGALzZdIOecguc5Eekgd8rHT+FECgYEAyZ7F
6s2UR+eNHi37NDQrjBLcjCF2jYxoCCwDl9IqxPCUXkmoiqklGNnoJPDfHUcMq/mC
hQjfGVBXEfxQy5BWBn/azNHoCxtffWyIqaJabR9eO/pON2zyaso0ePD1Cy9CmHoa
HadyfiH0K0UNl2f1Awpgq3Y+iVkjIo0wh5pxRq8CgYEAlN5oC4jfEmFyMwdxWKL0
eh/nji1Ki1Qq8zDhSGx0FnV2DA2qAd7UtKdPDeBO0mSQz0x/dveoorKxnSySAGmS
wRrgWZfqvc/LqX2kMkF4u46iy75C1v1w7NvQjTvrZkunwZUZoZ+S0ox6WN0LrO5D
BIoEF2Ev7flshY6vfkEV6zECgYBDqojMHADW/Qxsg4waYiP3V+EzGov6R5Qmofb2
vi9id0ekOV5aYxgzNfbmZvzKi6ziDtRSJ78QdNk0DRVkrGViuwhI023oRGCQ7JsV
K4rjsrJiuMgFbAgT9RcVO/FRtqPIHrqjFy6izGxxFTTRiq89PP9irEWivQrArtgJ
urinuwKBgQCnXeqv8R4Rc3AVYK4PPGhkJHdO603HLwyWKjZaTT5voHUr19gQs9uW
WW+XkxRkmQ3GiAFzrwM/aI/86E2+ZNQNHvKQ+3MYh0/npuJgumszNWlmwWfxZV5o
VLzTE2sMc4ivGY2f9WcCvOIVXwYnKbDOTDJ0GicdWPljnRsZSNBxKQ==
-----END RSA PRIVATE KEY-----`
	testBaseURLValid   = githubPublicAPI
	testBaseURLInvalid = "not a valid url"
)

func TestConfig_Update(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		new     *Config
		exp     *Config
		data    *framework.FieldData
		changed bool
		err     error
	}{
		{
			name: "Empty",
			new:  &Config{},
			exp:  &Config{},
			err:  errFieldDataNil,
		},
		{
			name: "Persists",
			new: &Config{
				AppID: testAppID1,
			},
			exp: &Config{
				AppID: testAppID1,
			},
			data:    &framework.FieldData{},
			changed: false,
		},
		{
			name: "Overwrites",
			new: &Config{
				AppID: testAppID1,
			},
			exp: &Config{
				AppID: testAppID2,
			},
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					keyAppID: testAppID2,
				},
			},
			changed: true,
		},
		{
			name: "OverwritesAndAdds",
			new: &Config{
				AppID: testAppID1,
			},
			exp: &Config{
				AppID:   testAppID2,
				InsID:   testInsID1,
				PrvKey:  testPrvKeyValid,
				BaseURL: testBaseURLValid,
			},
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					keyAppID:   testAppID2,
					keyInsID:   testInsID1,
					keyPrvKey:  testPrvKeyValid,
					keyBaseURL: testBaseURLValid,
				},
			},
			changed: true,
		},
		{
			name: "BaseURLInvalid",
			new:  &Config{},
			exp:  &Config{},
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					keyBaseURL: testBaseURLInvalid,
				},
			},
			changed: false,
			err:     errors.New(fmtErrUnableToParseBaseURL),
		},
		{
			name: "PrivateKeyNotPEMEncoded",
			new:  &Config{},
			exp:  &Config{},
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					keyPrvKey: "definitely not a PEM encoded private key",
				},
			},
			changed: false,
			err:     errKeyNotPEMFormat,
		},
		{
			name: "PrivateKeyInvalid",
			new:  &Config{},
			exp:  &Config{},
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					keyPrvKey: strings.Replace(testPrvKeyValid, "5", "6", 1),
				},
			},
			changed: false,
			err:     errors.New(fmtErrUnableToParsePrvKey),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.data != nil {
				var b = new(backend)
				tc.data.Schema = b.pathConfig().Fields
			}

			changed, err := tc.new.Update(tc.data)
			if tc.err != nil {
				assert.ErrorContains(t, err, tc.err.Error())
			} else {
				assert.NilError(t, err)
			}
			assert.Equal(t, changed, tc.changed)
			assert.DeepEqual(t, tc.new, tc.exp)
		})
	}
}
