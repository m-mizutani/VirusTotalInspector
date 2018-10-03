package main_test

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
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

// LoadTestConfig provides config data from "test.json".
// The method searches "test.json" toward upper directory
func LoadTestConfig(cfg interface{}) {
	cwd := os.Getenv("PWD")
	var fp *os.File
	var err error

	for cwd != "/" {
		cfgPath := filepath.Join(cwd, "test.json")

		cwd, _ = filepath.Split(strings.TrimRight(cwd, string(filepath.Separator)))

		fp, err = os.Open(cfgPath)
		if err == nil {
			break
		}
	}

	if fp == nil {
		log.Fatal("test.json is not found")
	}

	rawData, err := ioutil.ReadAll(fp)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(rawData, cfg)
	if err != nil {
		panic(err)
	}

	return
}

func TestAttributes(t *testing.T) {
	var cfg TestConfig
	LoadTestConfig(&cfg)

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
