// Package main is the Go 1.27 shape that crashed RTA: a concrete type
// with an exported generic method — a method declaring its own type
// parameters — that also becomes a runtime type. ssa.Program.MethodValue
// returns nil for the generic method (it cannot be lowered to SSA), and
// rta's addRuntimeType put that nil straight on its worklist.
//
// The corpus's generic-method fixture calls its generic methods directly,
// which never reaches MethodValue; this fixture boxes the type into an
// interface so RTA walks the exported method set.
package main

import "fmt"

// Processor has one method SSA can build and one it cannot.
type Processor struct {
	name string
}

// Describe is an ordinary method: it becomes an SSA function and an
// invoke-mode edge target.
func (p Processor) Describe() string {
	return p.name
}

// Convert is a generic method (Go 1.27): exported, so RTA must consider
// it callable via reflection, but unlowerable, so MethodValue answers nil.
func (p Processor) Convert[U any](in U) string {
	return fmt.Sprintf("%s: %v", p.name, in)
}

// Describer gives the analysis an invoke-mode call site on Processor.
type Describer interface {
	Describe() string
}

func describe(d Describer) string {
	return d.Describe()
}

func main() {
	// MakeInterface(Processor): Processor becomes a runtime type and its
	// whole exported method set — Convert included — is enumerated.
	var d Describer = Processor{name: "boxed"}
	println(describe(d))

	// A plain any-boxing of the same type, for the runtime-type path
	// without an invoke edge.
	var x any = Processor{name: "opaque"}
	println(x != nil)

	println(Processor{name: "direct"}.Convert(42))
}
