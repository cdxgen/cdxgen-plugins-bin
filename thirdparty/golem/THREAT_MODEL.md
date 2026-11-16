# Golem threat model

This document describes the security assumptions for running Golem against a Go repository. It is intentionally separate from the main README so implementation details and operational risk can evolve independently.

## Scope

Golem analyzes source code, package metadata, type information, and optional SSA graphs for a target Go module or workspace. It emits evidence about packages, files, imports, declarations, usages, build directives, native artifacts, endpoints, cryptographic APIs, call graphs, and data flows.

The primary trust boundary is between the Golem process and the target repository. The repository must be treated as untrusted input.

## What Golem should not do

Golem must not run `go:generate` commands. It records `//go:generate` directives as evidence only.

Golem must not copy raw secret-bearing content into the report. This includes environment values, command output, embedded file contents, private keys, tokens, passwords, and literal string values that appear to contain cryptographic material. It may report names, categories, counts, symbols, file paths, source ranges, and material types.

Golem should avoid network access initiated by its own logic. Package loading uses the local Go toolchain and module environment, so module downloads can still occur depending on the user's Go configuration. Run with a controlled module cache and proxy configuration when analyzing untrusted or sensitive projects.

## Build-shape environment overrides

Golem accepts build-shape overrides for the package load — the `--goexperiment` flag, `Options.Env` for API consumers, and `// golem:env` corpus annotations — and applies them to the environment the `go` command runs under. Keys are allowlisted to `GOEXPERIMENT`, `GOOS`, `GOARCH`, `GOAMD64` and `GOARM64`, and anything else is rejected with an error.

The allowlist is a command-execution boundary, not a convenience. Keys that change how the toolchain invokes other programs must never be settable this way: `GOFLAGS` accepts `-toolexec`, which substitutes the compiler and linker with attacker-chosen commands, and `GOENV` would redirect the toolchain's whole configuration file. Because corpus annotations are untrusted input carried inside analyzed repositories, a key that can execute code in the analyst's environment is exactly as dangerous arriving through a `golem:env` line as through any other path. `CGO_ENABLED` and every other `CGO_*` key are rejected for the same reason and can never arrive through an annotation or an option.

## cgo and the host C compiler

Loading a package that imports "C" makes the `go` command run the host C compiler and linker with flags the package itself chooses through its `#cgo` directives, `.syso` files and `#cgo pkg-config:` lines. On a Go toolchain older than go1.26.11 or go1.27.4 (CVE-2026-97033 through CVE-2026-97043), several of those inputs are command execution on the machine that loads the package.

Unless the process environment states `CGO_ENABLED`, Golem loads every package with `CGO_ENABLED=0`, so no `#cgo` input reaches the host compiler. The analyst opts in by exporting `CGO_ENABLED=1`; Golem then records the toolchain version, whether it carries the cgo flag fixes, and prints one warning on stderr when it does not. Files that import "C" are still read textually in every mode, so the report keeps the Go/C boundary, the `#cgo` variables and flag names, and the risk categories, without compiling anything.

Two loopholes remain by Go's design and widening them is the analyst's responsibility: `CGO_CFLAGS_ALLOW`, `CGO_LDFLAGS_ALLOW` and their CPPFLAGS, CXXFLAGS and FFLAGS variants re-allow refused flags for every package in the build, and flags placed directly in `CGO_CFLAGS` and friends are never checked at all. Golem records the names of the `CGO_*_ALLOW` and `CGO_*FLAGS` variables present in the load environment, never their values.

## Sensitive metadata

Even when raw secrets are omitted, reports can contain sensitive metadata. Examples include absolute source paths, package and module paths, private repository names, internal service names, endpoint paths, function names, dependency names, and source line numbers.

Treat a Golem report as internal analysis output unless it has been reviewed and redacted for the intended audience.

## Analysis limitations

Golem output is evidence for prioritization. A finding is not proof of exploitability, and the absence of a finding is not proof of safety.

Static analysis can miss behavior that depends on runtime configuration, reflection, plugins, dynamic loading, generated code not present in the loaded files, platform-specific files excluded by the selected build tags, or packages that fail to load. Diagnostics should be reviewed before relying on negative results.

Call graphs and data-flow slices are approximations. More conservative graph modes can add false positives. More precise or budget-limited modes can miss edges or truncate slices.

## Operator guidance

Run Golem in a clean working tree or disposable environment when analyzing untrusted code. Pin the Go version and build tags when reproducibility matters. Consider disabling networked module downloads through Go environment settings if the repository is not trusted.

Review diagnostics, package counts, build tags, test settings, and truncation reasons before consuming the output. Keep reports private unless metadata exposure is acceptable.
