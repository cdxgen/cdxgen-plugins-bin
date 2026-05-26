package lib

type Worker struct{ Prefix string }
type Handler func(string) string

type Greeter interface {
	Greet(string) string
}

func Hello(name string) string            { return "hello " + name }
func (w Worker) Greet(name string) string { return w.Prefix + name }
