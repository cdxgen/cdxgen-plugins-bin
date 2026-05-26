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
	Path            string            `json:"path"`
	PackageName     string            `json:"packageName,omitempty"`
	PackagePath     string            `json:"packagePath,omitempty"`
	Role            string            `json:"role,omitempty"`
	TestFile        bool              `json:"testFile,omitempty"`
	Compiled        bool              `json:"compiled"`
	Generated       bool              `json:"generated"`
	GeneratedBy     string            `json:"generatedBy,omitempty"`
	IgnoredReason   string            `json:"ignoredReason,omitempty"`
	Imports         []ImportUsage     `json:"imports,omitempty"`
	Declarations    []Declaration     `json:"declarations,omitempty"`
	Usages          []LibraryUsage    `json:"usages,omitempty"`
	BuildDirectives []BuildDirective  `json:"buildDirectives,omitempty"`
	SecuritySignals []SecuritySignal  `json:"securitySignals,omitempty"`
	Crypto          *CryptoEvidence   `json:"crypto,omitempty"`
	Properties      map[string]string `json:"properties,omitempty"`
}
type BuildDirective struct {
	Kind       string            `json:"kind"`
	Text       string            `json:"text,omitempty"`
	Command    string            `json:"command,omitempty"`
	Arguments  []string          `json:"arguments,omitempty"`
	Target     string            `json:"target,omitempty"`
	Patterns   []string          `json:"patterns,omitempty"`
	Range      Range             `json:"range"`
	Properties map[string]string `json:"properties,omitempty"`
}
type NativeArtifact struct {
	Path       string            `json:"path"`
	Kind       string            `json:"kind"`
	Extension  string            `json:"extension,omitempty"`
	PackageID  string            `json:"packageId,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}
type SecuritySignal struct {
	ID             string            `json:"id"`
	Category       string            `json:"category"`
	Severity       string            `json:"severity,omitempty"`
	Confidence     string            `json:"confidence,omitempty"`
	UsageScope     string            `json:"usageScope,omitempty"`
	PackagePath    string            `json:"packagePath,omitempty"`
	Symbol         string            `json:"symbol,omitempty"`
	Description    string            `json:"description,omitempty"`
	Recommendation string            `json:"recommendation,omitempty"`
	Range          Range             `json:"range"`
	Properties     map[string]string `json:"properties,omitempty"`
}
type CryptoLibrary struct {
	ID          string            `json:"id"`
	Path        string            `json:"path"`
	Family      string            `json:"family,omitempty"`
	Standard    bool              `json:"standard"`
	UsageScope  string            `json:"usageScope,omitempty"`
	PackagePath string            `json:"packagePath,omitempty"`
	Range       Range             `json:"range"`
	Properties  map[string]string `json:"properties,omitempty"`
}
type CryptoAsset struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	AssetType   string            `json:"assetType"`
	Primitive   string            `json:"primitive,omitempty"`
	Strength    string            `json:"strength,omitempty"`
	Standard    string            `json:"standard,omitempty"`
	OID         string            `json:"oid,omitempty"`
	PackagePath string            `json:"packagePath,omitempty"`
	Symbol      string            `json:"symbol,omitempty"`
	UsageScope  string            `json:"usageScope,omitempty"`
	Range       Range             `json:"range"`
	Properties  map[string]string `json:"properties,omitempty"`
}
type CryptoOperation struct {
	ID            string            `json:"id"`
	OperationType string            `json:"operationType"`
	Algorithm     string            `json:"algorithm,omitempty"`
	AssetID       string            `json:"assetId,omitempty"`
	PackagePath   string            `json:"packagePath,omitempty"`
	Symbol        string            `json:"symbol,omitempty"`
	UsageScope    string            `json:"usageScope,omitempty"`
	Range         Range             `json:"range"`
	Properties    map[string]string `json:"properties,omitempty"`
}
type CryptoMaterial struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Name        string            `json:"name,omitempty"`
	PackagePath string            `json:"packagePath,omitempty"`
	Symbol      string            `json:"symbol,omitempty"`
	UsageScope  string            `json:"usageScope,omitempty"`
	Range       Range             `json:"range"`
	Properties  map[string]string `json:"properties,omitempty"`
}
type CryptoProtocol struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Version     string            `json:"version,omitempty"`
	PackagePath string            `json:"packagePath,omitempty"`
	Symbol      string            `json:"symbol,omitempty"`
	UsageScope  string            `json:"usageScope,omitempty"`
	Range       Range             `json:"range"`
	Properties  map[string]string `json:"properties,omitempty"`
}
type CryptoFinding struct {
	ID             string            `json:"id"`
	RuleID         string            `json:"ruleId"`
	Severity       string            `json:"severity,omitempty"`
	Confidence     string            `json:"confidence,omitempty"`
	Summary        string            `json:"summary"`
	Recommendation string            `json:"recommendation,omitempty"`
	PackagePath    string            `json:"packagePath,omitempty"`
	UsageScope     string            `json:"usageScope,omitempty"`
	AssetID        string            `json:"assetId,omitempty"`
	OperationID    string            `json:"operationId,omitempty"`
	MaterialID     string            `json:"materialId,omitempty"`
	Range          Range             `json:"range"`
	Properties     map[string]string `json:"properties,omitempty"`
}
type CryptoEvidence struct {
	Libraries  []CryptoLibrary   `json:"libraries,omitempty"`
	Assets     []CryptoAsset     `json:"assets,omitempty"`
	Operations []CryptoOperation `json:"operations,omitempty"`
	Materials  []CryptoMaterial  `json:"materials,omitempty"`
	Protocols  []CryptoProtocol  `json:"protocols,omitempty"`
	Findings   []CryptoFinding   `json:"findings,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}
type ImportUsage struct {
	Path           string  `json:"path"`
	Name           string  `json:"name,omitempty"`
	AliasKind      string  `json:"aliasKind,omitempty"`
	UsageScope     string  `json:"usageScope,omitempty"`
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
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	Kind               string  `json:"kind"`
	TestKind           string  `json:"testKind,omitempty"`
	UsageScope         string  `json:"usageScope,omitempty"`
	PackagePath        string  `json:"packagePath,omitempty"`
	Receiver           string  `json:"receiver,omitempty"`
	Signature          string  `json:"signature,omitempty"`
	Type               string  `json:"type,omitempty"`
	Alias              bool    `json:"alias,omitempty"`
	AliasedType        string  `json:"aliasedType,omitempty"`
	AliasedPackagePath string  `json:"aliasedPackagePath,omitempty"`
	AliasedModule      *Module `json:"aliasedModule,omitempty"`
	Exported           bool    `json:"exported"`
	Range              Range   `json:"range"`
}
type LibraryUsage struct {
	ID              string            `json:"id"`
	Kind            string            `json:"kind"`
	Name            string            `json:"name"`
	QualifiedName   string            `json:"qualifiedName,omitempty"`
	PackagePath     string            `json:"packagePath,omitempty"`
	PackageName     string            `json:"packageName,omitempty"`
	UsageScope      string            `json:"usageScope,omitempty"`
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
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Kind       string `json:"kind,omitempty"`
	TestKind   string `json:"testKind,omitempty"`
	UsageScope string `json:"usageScope,omitempty"`
	Signature  string `json:"signature,omitempty"`
	Receiver   string `json:"receiver,omitempty"`
}
type PackageEvidence struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	PackagePath     string           `json:"packagePath"`
	Module          *Module          `json:"module,omitempty"`
	Standard        bool             `json:"standard"`
	Local           bool             `json:"local"`
	GoFiles         []string         `json:"goFiles,omitempty"`
	CompiledGoFiles []string         `json:"compiledGoFiles,omitempty"`
	OtherFiles      []string         `json:"otherFiles,omitempty"`
	Imports         []ImportUsage    `json:"imports,omitempty"`
	Declarations    []Declaration    `json:"declarations,omitempty"`
	Usages          []LibraryUsage   `json:"usages,omitempty"`
	BuildDirectives []BuildDirective `json:"buildDirectives,omitempty"`
	NativeArtifacts []NativeArtifact `json:"nativeArtifacts,omitempty"`
	SecuritySignals []SecuritySignal `json:"securitySignals,omitempty"`
	Crypto          *CryptoEvidence  `json:"crypto,omitempty"`
	Diagnostics     []Diagnostic     `json:"diagnostics,omitempty"`
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
	PackageCount           int `json:"packageCount"`
	ModuleCount            int `json:"moduleCount"`
	FileCount              int `json:"fileCount"`
	GeneratedFileCount     int `json:"generatedFileCount"`
	ImportCount            int `json:"importCount"`
	DeclarationCount       int `json:"declarationCount"`
	UsageCount             int `json:"usageCount"`
	RuntimeUsageCount      int `json:"runtimeUsageCount"`
	TestUsageCount         int `json:"testUsageCount"`
	BenchmarkUsageCount    int `json:"benchmarkUsageCount"`
	FuzzUsageCount         int `json:"fuzzUsageCount"`
	ExampleUsageCount      int `json:"exampleUsageCount"`
	BuildDirectiveCount    int `json:"buildDirectiveCount"`
	NativeArtifactCount    int `json:"nativeArtifactCount"`
	SecuritySignalCount    int `json:"securitySignalCount"`
	GoModReplaceCount      int `json:"goModReplaceCount"`
	GoModExcludeCount      int `json:"goModExcludeCount"`
	VendorModuleCount      int `json:"vendorModuleCount"`
	WorkspaceModuleCount   int `json:"workspaceModuleCount"`
	PrivateModuleHintCount int `json:"privateModuleHintCount"`
	LicenseFileModuleCount int `json:"licenseFileModuleCount"`
	CryptoLibraryCount     int `json:"cryptoLibraryCount"`
	CryptoAssetCount       int `json:"cryptoAssetCount"`
	CryptoOperationCount   int `json:"cryptoOperationCount"`
	CryptoMaterialCount    int `json:"cryptoMaterialCount"`
	CryptoProtocolCount    int `json:"cryptoProtocolCount"`
	CryptoFindingCount     int `json:"cryptoFindingCount"`
	DiagnosticCount        int `json:"diagnosticCount"`
}

type GoModDirective struct {
	Kind             string            `json:"kind"`
	ModulePath       string            `json:"modulePath,omitempty"`
	Version          string            `json:"version,omitempty"`
	TargetModulePath string            `json:"targetModulePath,omitempty"`
	TargetVersion    string            `json:"targetVersion,omitempty"`
	LocalReplacement bool              `json:"localReplacement,omitempty"`
	TargetPathKind   string            `json:"targetPathKind,omitempty"`
	Source           string            `json:"source,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}
type ModuleCompliance struct {
	Path                   string            `json:"path,omitempty"`
	Version                string            `json:"version,omitempty"`
	PURL                   string            `json:"purl,omitempty"`
	Main                   bool              `json:"main,omitempty"`
	Vendored               bool              `json:"vendored,omitempty"`
	PrivateModuleCandidate bool              `json:"privateModuleCandidate,omitempty"`
	LicenseFiles           []string          `json:"licenseFiles,omitempty"`
	Properties             map[string]string `json:"properties,omitempty"`
}
type SupplyChainEvidence struct {
	GoDirectiveVersion     string             `json:"goDirectiveVersion,omitempty"`
	ToolchainDirective     string             `json:"toolchainDirective,omitempty"`
	GoWorkPresent          bool               `json:"goWorkPresent,omitempty"`
	WorkspaceModuleCount   int                `json:"workspaceModuleCount,omitempty"`
	VendorDirectoryPresent bool               `json:"vendorDirectoryPresent,omitempty"`
	VendorModuleCount      int                `json:"vendorModuleCount,omitempty"`
	Replaces               []GoModDirective   `json:"replaces,omitempty"`
	Excludes               []GoModDirective   `json:"excludes,omitempty"`
	Modules                []ModuleCompliance `json:"modules,omitempty"`
	Properties             map[string]string  `json:"properties,omitempty"`
}
type Report struct {
	SchemaVersion   string               `json:"schemaVersion"`
	Tool            ToolInfo             `json:"tool"`
	Runtime         RuntimeInfo          `json:"runtime"`
	Options         AnalysisOptions      `json:"options"`
	RootModules     []Module             `json:"rootModules,omitempty"`
	Modules         []Module             `json:"modules,omitempty"`
	Packages        []PackageEvidence    `json:"packages,omitempty"`
	Files           []FileEvidence       `json:"files,omitempty"`
	Imports         []ImportUsage        `json:"imports,omitempty"`
	Declarations    []Declaration        `json:"declarations,omitempty"`
	Usages          []LibraryUsage       `json:"usages,omitempty"`
	BuildDirectives []BuildDirective     `json:"buildDirectives,omitempty"`
	NativeArtifacts []NativeArtifact     `json:"nativeArtifacts,omitempty"`
	SecuritySignals []SecuritySignal     `json:"securitySignals,omitempty"`
	Crypto          *CryptoEvidence      `json:"crypto,omitempty"`
	SupplyChain     *SupplyChainEvidence `json:"supplyChain,omitempty"`
	CallGraph       *CallGraph           `json:"callGraph,omitempty"`
	Diagnostics     []Diagnostic         `json:"diagnostics,omitempty"`
	Stats           Stats                `json:"stats"`
}
