package main_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	ar "github.com/m-mizutani/AlertResponder/lib"
	main "github.com/m-mizutani/VirusTotalInspector"

	"github.com/stretchr/testify/require"
)

// TestConfig is for test preference.
type TestConfig struct {
	SecretArn string `json:"secret_arn"`
}

func TestAttributes(t *testing.T) {
	var cfg TestConfig
	ar.LoadTestConfig(&cfg)

	task := ar.Task{
		ReportID: ar.NewReportID(),
		Attr: ar.Attribute{
			Type:    "ipaddr",
			Key:     "remote_addr",
			Value:   "195.22.26.248",
			Context: "remote",
		},
	}

	secretArnKey := "SECRET_ARN"
	os.Setenv(secretArnKey, cfg.SecretArn)
	defer os.Unsetenv(secretArnKey)
	res, err := main.SpyRemoteHost(task)
	require.NoError(t, err)
	assert.NotEqual(t, "", res.Title)
	assert.NotEqual(t, nil, res.RemoteHost)
}
