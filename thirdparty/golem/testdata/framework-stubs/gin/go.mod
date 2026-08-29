// A hermetic stub of github.com/gin-gonic/gin. Fixtures require this module
// through a filesystem `replace`, so the module path stays
// github.com/gin-gonic/gin — golem's framework classifier matches on the
// resolved import path, not the local file location.
module github.com/gin-gonic/gin

go 1.25
