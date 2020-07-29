// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build functionaltests

package tests

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"text/template"

	aconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/security/module"
)

var defaultPolicy = `---
version: 1.0.0
rules:
  - id: credential_modified
    description: credential files modified using unknown tool
    expression: >-
      (open.filename == "/etc/shadow" || open.filename == "/etc/gshadow") &&
      process.name not in ["vipw", "vigr"]
    tags:
      mitre: T1003
  - id: memory_dump
    description: memory dump
    expression: >-
      open.filename =~ "/proc/*" && open.basename in ["maps", "mem"]
    tags:
      mitre: T1003
  - id: logs_altered
    description: log entries removed
    expression: >-
      (open.filename =~ "/var/log/*" && open.flags & O_TRUNC > 0)
    tags:
      mitre: T1070
  - id: logs_removed
    description: log entries removed
    expression: >-
      unlink.filename =~ "/var/log/*"
    tags:
      mitre: T1070
  - id: permissions_changed
    description: permissions change on sensible files
    expression: >-
      chmod.filename =~ "/etc/*" || chmod.filename =~ "/etc/*" ||
      chmod.filename =~ "/sbin/*" || chmod.filename =~ "/usr/sbin/*" ||
      chmod.filename =~ "/usr/local/sbin*" || chmod.filename =~ "/usr/bin/local/*" ||
      chmod.filename =~ "/var/log/*" || chmod.filename =~ "/usr/lib/*"
    tags:
      mitre: T1099
  - id: hidden_file
    description: hidden file creation
    expression: >-
      open.basename =~ ".*" && open.flags & O_CREAT > 0
    tags:
      mitre: T1158
  - id: kernel_module
    description: new file in kernel module location
    expression: >-
      open.filename =~ "/lib/modules/*" && open.flags & O_CREAT > 0
    tags:
      mitre: T1215
`

func TestConfig(t *testing.T) {
	tmpl, err := template.New("test_config").Parse(testConfig)
	if err != nil {
		t.Fatal(err)
	}

	root, err := ioutil.TempDir("", "test-secagent-root")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	if err := ioutil.WriteFile(path.Join(root, "default.policy"), []byte(defaultPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	buffer := new(bytes.Buffer)
	if err := tmpl.Execute(buffer, map[string]interface{}{
		"TestPoliciesDir": root,
	}); err != nil {
		t.Fatal(err)
	}

	aconfig.Datadog.SetConfigType("yaml")
	if err := aconfig.Datadog.ReadConfig(buffer); err != nil {
		t.Fatal(err)
	}

	_, err = module.NewModule(nil)
	if err != nil {
		t.Fatal(err)
	}
}
