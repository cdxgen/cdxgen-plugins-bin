package main

import (
	"github.com/aquasecurity/trivy/pkg/commands"
	"os"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
)

func main() {
    os.Setenv("TRIVY_OFFLINE_SCAN", "true")
    os.Setenv("TRIVY_DISABLE_TELEMETRY", "true")
    os.Setenv("TRIVY_SKIP_VERSION_CHECK", "true")
	os.Exit(run())
}

func run() int {
	exitStatus := 0
	app := commands.NewApp()
	if err := app.Execute(); err != nil {
		exitStatus = 1
	}
	return exitStatus
}
