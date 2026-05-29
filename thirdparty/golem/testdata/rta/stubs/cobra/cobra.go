package cobra

type Command struct {
	Use string
	Run func(*Command, []string)
}
