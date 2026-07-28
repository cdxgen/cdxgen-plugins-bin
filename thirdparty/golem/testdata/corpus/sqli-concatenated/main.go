package sqliconcatenated

import (
	"database/sql"
	"net/http"
)

// A query built by concatenation is the canonical Go SQL injection. It went
// undetected until the built-in patterns were normalised into the notation the
// SSA printer uses: the pattern read "database/sql.(*DB).Query" while the symbol
// reads "(*database/sql.DB).Query", and the substring test between them could
// never succeed.
// golem:want flow source=http-input sink=data
func Handler(r *http.Request, db *sql.DB) {
	name := r.FormValue("name")
	_, _ = db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
