package analyzer

import (
	"go/token"
	"io"
	"time"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

const SchemaVersion = "https://cdxgen.github.io/cdxgen-plugins-bin/golem/schema/v1"

type Options struct {
	Dir                             string
	NoRecurse                       bool
	IncludeAllFlows                 bool
	Patterns                        []string
	BuildTags                       []string
	Tests                           bool
	IncludeStdlib                   bool
	IncludeLocal                    bool
	CallGraphMode                   string
	DataFlowMode                    string
	DataFlowPacks                   []string
	DataFlowConfig                  string
	DataFlowMax                     int
	DataFlowCallGraphMode           string
	DataFlowWorkers                 int
	DataFlowLargeRepoFunctions      int
	DataFlowMaxFunctionInstructions int
	DataFlowMaxTraceNodes           int
	DataFlowMaxTraceEdges           int
	DataFlowSkipGenerated           bool
	DataFlowSkipTests               bool
	MaxProcs                        int
	MemoryLimit                     int64
	Progress                        bool
	ProgressInterval                time.Duration
	ProgressWriter                  io.Writer
	IncludeSSA                      bool
	IncludeSources                  bool
	ToolVersion                     string
}

type Analyzer struct {
	fset          *token.FileSet
	options       Options
	packageByPath map[string]*packages.Package
	moduleByPath  map[string]*model.Module
	rootModules   map[string]*model.Module
}
