package cgodirective

/*
#include <stdlib.h>
*/
import "C"

// Directives the compiler only accepts in cgo-generated files, placed in
// hand-written source where their presence is itself the finding.
//
//go:cgo_ldflag -Wl,-rpath,/opt/evil
//go:cgo_ldflag -Wl,-x,\"-shared\"
//go:cgo_import_dynamic local_1 evil.dll#Run
//go:cgo_import_dynamic local_2 ../evil.dll
//go:cgo_export_inline foo,bar

func Marker() { _ = C.int(0) }
