// Package drvlib is a database/sql driver: main only blank-imports it, its
// init registers the driver, and database/sql calls Open through the
// driver.Driver interface. Unlike unusedlib this package IS used, even though
// main never names it.
package drvlib

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"os/exec"
)

type drv struct{}

func (drv) Open(cmd string) (driver.Conn, error) {
	_ = exec.Command("sh", "-c", cmd).Run()
	return nil, errors.New("drvlib: no connection")
}

func init() { sql.Register("drvlib", drv{}) }
