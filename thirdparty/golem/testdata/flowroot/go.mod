module example.com/golem/flowroot

go 1.25

require (
	example.com/drvlib v0.0.0
	example.com/fnvallib v0.0.0
	example.com/ifacelib v0.0.0
	example.com/unusedlib v0.0.0
	example.com/usedlib v0.0.0
)

replace example.com/usedlib => ./stubs/usedlib

replace example.com/unusedlib => ./stubs/unusedlib

replace example.com/ifacelib => ./stubs/ifacelib

replace example.com/fnvallib => ./stubs/fnvallib

replace example.com/drvlib => ./stubs/drvlib
