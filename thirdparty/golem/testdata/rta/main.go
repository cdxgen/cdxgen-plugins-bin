package main

import (
	"net/http"

	"github.com/spf13/cobra"
)

func handler(http.ResponseWriter, *http.Request) {}

func worker() {}

func commandRun(*cobra.Command, []string) {
	worker()
}

var rootCmd = &cobra.Command{Run: commandRun}

func init() {
	http.HandleFunc("/rta", handler)
}

func main() {
	go worker()
	_ = rootCmd
}
