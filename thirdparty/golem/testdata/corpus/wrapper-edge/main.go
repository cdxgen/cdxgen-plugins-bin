package wrapperedge

import "fmt"

// WrapperEdge verifies that bound-method thunks and interface wrappers are not
// dropped from the call graph. When a method is reached through an interface, the
// SSA builder inserts a bound-method wrapper (fn.Synthetic == "bound method wrapper").
// golem must retain that synthetic node and the edges that pass through it.

type Greeter interface {
	Greet(string) string
}

type simpleGreeter struct{}

func (simpleGreeter) Greet(name string) string {
	return fmt.Sprintf("hello %s", name)
}

// greetThroughInterface dispatches through the interface, which forces a
// bound-method thunk in the SSA.
func greetThroughInterface(g Greeter, name string) string {
	return g.Greet(name)
}

// Entry calls the interface path; the call graph must show:
//
//	golem:want edge from=~wrapper-edge.greetThroughInterface to=~simpleGreeter calltype=interface
//	golem:want edge from=~wrapper-edge.Entry to=~wrapper-edge.greetThroughInterface
//	golem:want edge from=~wrapper-edge.init to=~wrapper-edge.Entry
//
// The interface edge exercises defect 1: the bound-method wrapper node
// ((*simpleGreeter).Greet) must be retained for the edge to survive.
func Entry() string {
	return greetThroughInterface(simpleGreeter{}, "world")
}

func init() {
	_ = Entry()
}
