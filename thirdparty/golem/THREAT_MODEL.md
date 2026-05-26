# Golem threat model

This document describes the security assumptions for running Golem against a Go repository. It is intentionally separate from the main README so implementation details and operational risk can evolve independently.

## Scope

Golem analyzes source code, package metadata, type information, and optional SSA graphs for a target Go module or workspace. It emits evidence about packages, files, imports, declarations, usages, build directives, native artifacts, endpoints, cryptographic APIs, call graphs, and data flows.

The primary trust boundary is between the Golem process and the target repository. The repository must be treated as untrusted input.

## What Golem should not do

Golem must not run `go:generate` commands. It records `//go:generate` directives as evidence only.

Golem must not copy raw secret-bearing content into the report. This includes environment values, command output, embedded file contents, private keys, tokens, passwords, and literal string values that appear to contain cryptographic material. It may report names, categories, counts, symbols, file paths, source ranges, and material types.

Golem should avoid network access initiated by its own logic. Package loading uses the local Go toolchain and module environment, so module downloads can still occur depending on the user's Go configuration. Run with a controlled module cache and proxy configuration when analyzing untrusted or sensitive projects.

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
