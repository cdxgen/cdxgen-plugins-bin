package main

import (
	alias "example.com/golem/dep/lib"
)

type LocalWorker = alias.Worker
type HandlerAlias = alias.Handler

var globalHello = alias.Hello

func main() {
	fn := alias.Hello
	_ = fn("local")
	_ = globalHello("global")
	worker := alias.Worker{Prefix: "hi "}
	method := worker.Greet
	_ = method("method")
	methodExpr := alias.Worker.Greet
	_ = methodExpr(worker, "expr")
	var typed HandlerAlias = alias.Hello
	_ = typed("typed")
	_ = useInterface(worker)
}

func useInterface(g alias.Greeter) string {
	return g.Greet("iface")
}
