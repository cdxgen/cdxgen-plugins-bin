package sqliparameterizednegative

import (
	"database/sql"
	"net/http"
)

// A parameterized query must not be reported. This is now a real test: the sink
// is matched, and the expectation holds because only the query string is a sink
// argument. The bound parameters that follow it are sent out of band by the
// driver, so treating them as sink arguments would report every correctly
// parameterised query as an injection.
// golem:want-not flow source=http-input sink=data
func Handler(r *http.Request, db *sql.DB) {
	q := r.FormValue("q")
	// This is properly parameterized - should not be flagged
	_, _ = db.Query("SELECT * FROM users WHERE name = ?", q)
}
