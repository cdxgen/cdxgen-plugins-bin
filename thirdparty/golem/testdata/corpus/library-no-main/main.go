package librarynomain

import "fmt"

// Library-no-main: a library package with no main function. Without --roots
// exported, only init functions are roots for RTA. This fixture verifies that
// the call graph is not entirely empty for a library module.
//
//	golem:want edge from=~library-no-main.init to=~library-no-main.PublicHelper
//	golem:want reachable symbol=~library-no-main.PublicHelper

// PublicHelper is an exported helper that init calls.
func PublicHelper(name string) string {
	return fmt.Sprintf("hello %s", name)
}

func init() {
	_ = PublicHelper("world")
}
