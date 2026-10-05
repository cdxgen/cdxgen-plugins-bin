// Package flowroot is the fixture for per-slice root reachability. Every
// stub library carries the same parameter-to-sink flow; main reaches them in
// different ways:
//
//   - usedlib: a direct call
//   - ifacelib: interface dispatch only
//   - fnvallib: a function value from a map only
//   - drvlib: a blank import whose init registers a database/sql driver
//   - unusedlib: a blank import and nothing else, so it must stay unrooted
package main

import (
	"database/sql"
	"os"

	"example.com/fnvallib"
	"example.com/ifacelib"
	"example.com/usedlib"

	_ "example.com/drvlib"
	_ "example.com/unusedlib"
)

func main() {
	if len(os.Args) < 2 {
		return
	}
	usedlib.Run(os.Args[1])
	ifacelib.New().Run(os.Args[1])
	fnvallib.Handlers["run"](os.Args[1])
	if db, err := sql.Open("drvlib", os.Args[1]); err == nil {
		_ = db.Ping()
	}
}
