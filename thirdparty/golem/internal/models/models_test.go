package models_test

import (
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/models"
)

func TestModelLoad(t *testing.T) {
	db := models.NewDB()
	if err := db.LoadBuiltins(); err != nil {
		t.Fatal(err)
	}
	t.Logf("Loaded %d entries", len(db.Entries()))

	// Check specific entries
	for _, e := range db.Entries() {
		if e.Package == "os/exec" && e.Function == "Command" {
			t.Logf("Found Command sink: receiver=%q kind=%s", e.Receiver, e.Kind)
		}
		if e.Package == "net/http" && e.Receiver == "*Request" && e.Function == "FormValue" {
			t.Logf("Found FormValue source: id=%s kind=%s", e.ID, e.Kind)
		}
	}

	unmatched := db.UnmatchedSymbols()
	t.Logf("Unmatched symbols: %d", len(unmatched))
	if len(unmatched) > 0 {
		t.Logf("First unmatched: %s", unmatched[0])
	}
}
