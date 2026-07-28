package loggingsecret

import (
	"log"
	"os"
)

// An environment variable that is not secret-shaped, logged deliberately. The
// environment source carries both "environment" and "secret" taint kinds, so a
// rule that treats every environment read as a credential leak floods a real
// codebase with findings for ordinary configuration logging.
// golem:want flow source=environment sink=logging
// golem:want-not flow source=http-input sink=logging
func Main() {
	log.Printf("listening on %s", os.Getenv("PORT"))
}
