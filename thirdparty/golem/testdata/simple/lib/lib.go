package lib

type Greeter struct {
	Prefix string
}

func Hello(name string) string {
	return "hello " + name
}
func (g Greeter) Greet(name string) string {
	return g.Prefix + name
}
