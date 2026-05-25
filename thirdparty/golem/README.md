# golem
Golem (Go Library Evidence Mapper) is a native Go helper for cdxgen. It analyzes Go source projects with the Go toolchain and emits detailed semantic evidence about packages, modules, imports, declarations, type-resolved library usages, build directives, native interop artifacts, security-sensitive API signals, and optional call graphs.
## Usage
```bash
golem analyze --dir /path/to/go/project --format json --out golem.json
golem analyze --dir . --callgraph static --format graphml --out callgraph.graphml
golem analyze --dir . --callgraph rta --format gexf --out callgraph.gexf
golem analyze --dir . --callgraph pointer --format json --out golem-pointer.json
```
## Call graph modes
- `none` — default; source/library evidence only.
- `static` — fast static SSA call graph.
- `rta` — Rapid Type Analysis from discovered `init` and `main` roots.
- `pointer` — points-to call graph for main packages. This is the most expensive mode.
## Output formats
- `json` — complete evidence schema.
- `graphml` — call graph sidecar suitable for graph tools.
- `gexf` — call graph sidecar suitable for Gephi and similar tools.
Graph formats require a non-`none` call graph mode.

## Security and compliance evidence

The JSON report includes Go-specific evidence useful for AppSec and compliance review:

- build constraints from `//go:build` and legacy `// +build`
- `//go:generate` directives without executing generator commands
- `//go:embed` patterns, targets, and safe risk indicators for embedded credentials or crypto material
- native sidecar files such as C/C++/Objective-C/assembly/native object files
- cgo directives and `import "C"`/`C.symbol` signals when present
- security-sensitive API signals for unsafe, reflection, syscall, plugin loading, process execution, environment access, HTTP, TLS, weak crypto, weak randomness, archive handling, templates, database opens, and filesystem writes
- focused heuristics such as `tls.Config{InsecureSkipVerify:true}`

Signal values are categories/counts/symbol names and source locations only; `golem` does not copy raw environment values, command output, embedded file contents, or secrets into JSON.

## Build

```bash
go test ./...
make all
```

The Makefile cross-compiles static binaries for Linux, macOS, and Windows targets used by `cdxgen-plugins-bin`.

## Real repository smoke tests

```bash
go build -trimpath -ldflags "-s -w" -o build/golem-darwin-arm64 ./cmd/golem
python3 scripts/real-e2e.py --golem ./build/golem-darwin-arm64
```

The real E2E script is opt-in because it clones public GitHub repositories and can trigger Go module downloads while loading package metadata.