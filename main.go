package main

import (
	"fmt"
	"os"

	ar "github.com/m-mizutani/AlertResponder/lib"
)

func spyRemoteHost(task ar.Task) (*ar.Section, error) {
	ar.Dump("task", task)
	if task.Attr.Context != "remote" || task.Attr.Type != "ipaddr" {
		return nil, nil // No report
	}

	section := ar.Section{}
	section.Title = fmt.Sprintf("Spy Remote Host: %s", task.Attr.Value)
	return &section, nil
}

func main() {
	tableName := os.Getenv("REPORT_DATA")
	ar.Inspect(spyRemoteHost, tableName)
}
