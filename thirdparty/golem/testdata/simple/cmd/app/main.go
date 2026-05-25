package main

import (
	"example.com/golem/simple/lib"
	"fmt"
)

func main() {
	fmt.Println(run("golem"))
}
func run(name string) string {
	g := lib.Greeter{Prefix: lib.Hello("hi ")}
	return g.Greet(name)
}
