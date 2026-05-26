package main

import (
	"testing"

	alias "example.com/golem/dep/lib"
)

func TestAliasHello(t *testing.T) {
	if alias.Hello("test") == "" {
		t.Fatal("empty greeting")
	}
}

func BenchmarkAliasHello(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = alias.Hello("bench")
	}
}

func FuzzAliasHello(f *testing.F) {
	f.Add("seed")
	f.Fuzz(func(t *testing.T, value string) {
		_ = alias.Hello(value)
	})
}

func ExampleAliasHello() {
	_ = alias.Hello("example")
}
