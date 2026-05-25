package model

type Position struct {
	Filename string `json:"filename,omitempty"`
	Offset   int    `json:"offset,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}
type ToolInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}
type RuntimeInfo struct {
	GOOS       string   `json:"goos"`
	GOARCH     string   `json:"goarch"`
	GoVersion  string   `json:"goVersion"`
	Goroot     string   `json:"goroot,omitempty"`
	WorkingDir string   `json:"workingDir,omitempty"`
	Patterns   []string `json:"patterns,omitempty"`
	BuildTags  []string `json:"buildTags,omitempty"`
	Tests      bool     `json:"tests"`
}
type AnalysisOptions struct {
	Directory      string   `json:"directory"`
	Patterns       []string `json:"patterns"`
	BuildTags      []string `json:"buildTags,omitempty"`
	Tests          bool     `json:"tests"`
	IncludeStdlib  bool     `json:"includeStdlib"`
	IncludeLocal   bool     `json:"includeLocal"`
	CallGraphMode  string   `json:"callGraphMode"`
	IncludeSSA     bool     `json:"includeSsa"`
	IncludeSources bool     `json:"includeSources"`
}
type Diagnostic struct {
	PackageID string   `json:"packageId,omitempty"`
	Position  Position `json:"position,omitempty"`
	Message   string   `json:"message"`
	Kind      string   `json:"kind,omitempty"`
}
type Module struct {
	Path      string  `json:"path,omitempty"`
	Version   string  `json:"version,omitempty"`
	Dir       string  `json:"dir,omitempty"`
	GoMod     string  `json:"goMod,omitempty"`
	GoVersion string  `json:"goVersion,omitempty"`
	Main      bool    `json:"main,omitempty"`
	PURL      string  `json:"purl,omitempty"`
	Replace   *Module `json:"replace,omitempty"`
}
type FileEvidence struct {
	Path          string         `json:"path"`
	PackageName   string         `json:"packageName,omitempty"`
	PackagePath   string         `json:"packagePath,omitempty"`
	Compiled      bool           `json:"compiled"`
	Generated     bool           `json:"generated"`
	IgnoredReason string         `json:"ignoredReason,omitempty"`
	Imports       []ImportUsage  `json:"imports,omitempty"`
	Declarations  []Declaration  `json:"declarations,omitempty"`
	Usages        []LibraryUsage `json:"usages,omitempty"`
}
type ImportUsage struct {
	Path           string  `json:"path"`
	Name           string  `json:"name,omitempty"`
	AliasKind      string  `json:"aliasKind,omitempty"`
	PackageID      string  `json:"packageId,omitempty"`
	PackageName    string  `json:"packageName,omitempty"`
	Module         *Module `json:"module,omitempty"`
	Standard       bool    `json:"standard"`
	Local          bool    `json:"local"`
	Direct         bool    `json:"direct"`
	Range          Range   `json:"range"`
	Resolved       bool    `json:"resolved"`
	ResolutionNote string  `json:"resolutionNote,omitempty"`
}
type Declaration struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	PackagePath string `json:"packagePath,omitempty"`
	Receiver    string `json:"receiver,omitempty"`
	Signature   string `json:"signature,omitempty"`
	Type        string `json:"type,omitempty"`
	Exported    bool   `json:"exported"`
	Range       Range  `json:"range"`
}
type LibraryUsage struct {
	ID              string            `json:"id"`
	Kind            string            `json:"kind"`
	Name            string            `json:"name"`
	QualifiedName   string            `json:"qualifiedName,omitempty"`
	PackagePath     string            `json:"packagePath,omitempty"`
	PackageName     string            `json:"packageName,omitempty"`
	Module          *Module           `json:"module,omitempty"`
	Standard        bool              `json:"standard"`
	Local           bool              `json:"local"`
	SymbolKind      string            `json:"symbolKind,omitempty"`
	Type            string            `json:"type,omitempty"`
	Signature       string            `json:"signature,omitempty"`
	Receiver        string            `json:"receiver,omitempty"`
	Method          bool              `json:"method"`
	Builtin         bool              `json:"builtin"`
	Call            bool              `json:"call"`
	ArgumentCount   int               `json:"argumentCount,omitempty"`
	Variadic        bool              `json:"variadic,omitempty"`
	Range           Range             `json:"range"`
	Enclosing       *EnclosingContext `json:"enclosing,omitempty"`
	ImportPath      string            `json:"importPath,omitempty"`
	ImportAlias     string            `json:"importAlias,omitempty"`
	ImportAliasKind string            `json:"importAliasKind,omitempty"`
	Properties      map[string]string `json:"properties,omitempty"`
}
type EnclosingContext struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Signature string `json:"signature,omitempty"`
	Receiver  string `json:"receiver,omitempty"`
}
type PackageEvidence struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	PackagePath     string         `json:"packagePath"`
	Module          *Module        `json:"module,omitempty"`
	Standard        bool           `json:"standard"`
	Local           bool           `json:"local"`
	GoFiles         []string       `json:"goFiles,omitempty"`
	CompiledGoFiles []string       `json:"compiledGoFiles,omitempty"`
	OtherFiles      []string       `json:"otherFiles,omitempty"`
	Imports         []ImportUsage  `json:"imports,omitempty"`
	Declarations    []Declaration  `json:"declarations,omitempty"`
	Usages          []LibraryUsage `json:"usages,omitempty"`
	Diagnostics     []Diagnostic   `json:"diagnostics,omitempty"`
}
type CallGraph struct {
	Mode        string          `json:"mode"`
	Algorithm   string          `json:"algorithm,omitempty"`
	Nodes       []CallGraphNode `json:"nodes,omitempty"`
	Edges       []CallGraphEdge `json:"edges,omitempty"`
	Diagnostics []Diagnostic    `json:"diagnostics,omitempty"`
	Stats       GraphStats      `json:"stats"`
}
type GraphStats struct {
	NodeCount int `json:"nodeCount"`
	EdgeCount int `json:"edgeCount"`
}
type CallGraphNode struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Label       string   `json:"label,omitempty"`
	Kind        string   `json:"kind"`
	PackagePath string   `json:"packagePath,omitempty"`
	PackageName string   `json:"packageName,omitempty"`
	Module      *Module  `json:"module,omitempty"`
	PURL        string   `json:"purl,omitempty"`
	Standard    bool     `json:"standard"`
	Local       bool     `json:"local"`
	External    bool     `json:"external"`
	Synthetic   bool     `json:"synthetic,omitempty"`
	Signature   string   `json:"signature,omitempty"`
	Receiver    string   `json:"receiver,omitempty"`
	Position    Position `json:"position,omitempty"`
}
type CallGraphEdge struct {
	ID          string            `json:"id"`
	SourceID    string            `json:"sourceId"`
	TargetID    string            `json:"targetId"`
	SourceName  string            `json:"sourceName,omitempty"`
	TargetName  string            `json:"targetName,omitempty"`
	CallType    string            `json:"callType"`
	Static      bool              `json:"static"`
	Synthetic   bool              `json:"synthetic,omitempty"`
	Position    Position          `json:"position,omitempty"`
	Description string            `json:"description,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}
type Stats struct {
	PackageCount     int `json:"packageCount"`
	ModuleCount      int `json:"moduleCount"`
	FileCount        int `json:"fileCount"`
	ImportCount      int `json:"importCount"`
	DeclarationCount int `json:"declarationCount"`
	UsageCount       int `json:"usageCount"`
	DiagnosticCount  int `json:"diagnosticCount"`
}
type Report struct {
	SchemaVersion string            `json:"schemaVersion"`
	Tool          ToolInfo          `json:"tool"`
	Runtime       RuntimeInfo       `json:"runtime"`
	Options       AnalysisOptions   `json:"options"`
	RootModules   []Module          `json:"rootModules,omitempty"`
	Modules       []Module          `json:"modules,omitempty"`
	Packages      []PackageEvidence `json:"packages,omitempty"`
	Files         []FileEvidence    `json:"files,omitempty"`
	Imports       []ImportUsage     `json:"imports,omitempty"`
	Declarations  []Declaration     `json:"declarations,omitempty"`
	Usages        []LibraryUsage    `json:"usages,omitempty"`
	CallGraph     *CallGraph        `json:"callGraph,omitempty"`
	Diagnostics   []Diagnostic      `json:"diagnostics,omitempty"`
	Stats         Stats             `json:"stats"`
}
