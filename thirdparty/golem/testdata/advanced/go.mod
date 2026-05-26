module example.com/golem/advanced
go 1.25
require example.com/golem/dep v0.0.0
replace example.com/golem/dep => ../dep
exclude example.com/unused/module v1.2.3
