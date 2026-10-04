module example.com/golem/flowroot

go 1.25

require (
	example.com/usedlib v0.0.0
	example.com/unusedlib v0.0.0
)

replace example.com/usedlib => ./stubs/usedlib

replace example.com/unusedlib => ./stubs/unusedlib
