package main

import (
	"net/http"

	"github.com/spf13/cobra"
)

type Router struct{}

func handler(http.ResponseWriter, *http.Request) {}

func verbHandler(http.ResponseWriter, *http.Request) {}

func worker() {}

func deadHandler(http.ResponseWriter, *http.Request) {}

func nestedHandler(http.ResponseWriter, *http.Request) {}

func commandRun(*cobra.Command, []string) {
	worker()
}

func (*Router) Get(string, func(http.ResponseWriter, *http.Request)) {}

var rootCmd = &cobra.Command{Run: commandRun}
var router = &Router{}

func deadRegistration() {
	http.HandleFunc("/dead", deadHandler)
}

func nestedRegistration() {
	http.HandleFunc("/nested", nestedHandler)
}

func init() {
	http.HandleFunc("/rta", handler)
	router.Get("/verb", verbHandler)
	nestedRegistration()
}

func main() {
	go worker()
	_ = rootCmd
}
