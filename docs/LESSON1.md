# Lesson 1: First Go evidence report with golem

## Learning objective

Generate your first golem report for a Go project, understand the shape of the JSON, and answer the two questions every Go review starts with: what does this module depend on, and what does its code actually use.

## Pre-requisites

- Go 1.27 or later (to build golem)
- any Go module on disk; this lesson uses golem itself as the sample

## Build golem

From a checkout of this repository:

```bash
cd thirdparty/golem
go build -o /tmp/golem ./cmd/golem
```

If cdxgen installed the plugins package on your machine, the binary already exists as `golem-<platform>` somewhere under `node_modules/@cdxgen/`, and everything below works the same with `GOLEM_CMD` pointed at it.

## Analyze a module

Use golem's own source as the target:

```bash
/tmp/golem analyze --dir thirdparty/golem --out /tmp/golem.json
```

The command finishes in seconds on this repository. The JSON is minified; look at the top-level keys first:

```bash
jq 'keys' /tmp/golem.json
```

You will see sections for packages, files, imports, declarations, usages, security signals, api endpoints, services, external URLs, stats, and metadata. Everything is evidence with source ranges, which is why the report from a few hundred lines of Go is a few hundred kilobytes and not gigabytes.

## Follow one dependency end to end

Pick a package you know the target imports. For golem itself, `golang.org/x/tools` is the big one:

```bash
jq -r '.imports[] | select(.Path | startswith("golang.org/x/tools")) | .Path' /tmp/golem.json | head
```

Each import record tells you whether the package is local, standard library, or external, and which module and version satisfy it. The `usages` section is where it gets interesting: imports say what is referenced, usages say what is actually called, with type resolution, so a package imported for one type does not get credit for every symbol in it:

```bash
jq '[.usages[] | select(.Call == true)] | length' /tmp/golem.json
```

## Look at the attack surface hints

The `securitySignals` section records type-resolved use of security-sensitive APIs, each with a category, confidence, source position, and recommendation:

```bash
jq -r '.securitySignals[] | [.severity, .symbol, .description] | @tsv' /tmp/golem.json | head
```

The `apiEndpoints` section lists HTTP routes the source registers. golem's own source registers none, so target something with a server to see it filled, which is the subject of Lesson 2.

## Check the version ceiling

golem records the language version it was built with:

```bash
jq '.runtime.languageVersion' /tmp/golem.json
```

A module declaring a newer `go` directive than this ceiling cannot be type-checked correctly, and golem tells you so through a `go-version` diagnostic instead of failing mysteriously. If you see that diagnostic, rebuild golem with a newer toolchain rather than debugging phantom type errors.

## What you learned

- golem loads a module with the real Go toolchain, so its evidence matches what the compiler sees
- imports, declarations, and usages are three different facts: referenced, defined, and actually called
- every record carries a source range, so findings are jump-to-code rather than file-level noise
- the report self-describes its limits through diagnostics such as the language version ceiling

Next: [Lesson 2, call graphs, reachability, and data flow](LESSON2.md).
