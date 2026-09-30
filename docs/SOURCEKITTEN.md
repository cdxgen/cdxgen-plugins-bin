# sourcekitten: Swift semantics via SourceKit

Swift projects declare dependencies in `Package.swift`, but knowing what the code actually imports, which modules and frameworks exist, and how the source is structured requires Swift language semantics. [SourceKitten](https://github.com/jpsim/SourceKitten) is the standard command-line bridge to Apple's SourceKit service, the same engine Xcode uses for parsing and indexing. This repository builds it and ships it so cdxgen can produce evidence-backed Swift BOMs.

The binary is built from the pinned upstream release with `swift build -c release` by the script in `thirdparty/sourcekitten`. It is not forked. The packaging step also attaches a CycloneDX SBOM of the Swift dependencies used to build it.

cdxgen invokes sourcekitten for Swift evidence (`cdxgen -t swift --evidence`, `evinse -l swift`) when the binary is present. A custom build can be wired in with `SOURCEKITTEN_CMD`.

## What it gives cdxgen

Module and framework discovery in a Swift project, source parsing through SourceKit's JSON API, and the dependency facts cdxgen merges into the BOM for Swift packages. With it, Swift BOMs describe what the source uses rather than only what the manifest lists.

## Direct usage

sourcekitten is a general Swift tool, and everything it can do is available when you drive it yourself. The two subcommands most useful for reviewing a project the way cdxgen sees it:

```bash
sourcekitten structure --file Sources/App/Main.swift
sourcekitten syntax --file Sources/App/Main.swift
```

`structure` returns the syntax map and declaration structure of a file as JSON. When investigating what cdxgen recorded for a Swift project, running sourcekitten directly on the same tree shows you the underlying evidence.

## Platforms

darwin-arm64 and darwin-amd64 only. The macOS builds load SourceKit from Xcode or from an installed `.xctoolchain`, and macOS Swift has a stable ABI.

There is no Linux build ([#119](https://github.com/cdxgen/cdxgen-plugins-bin/issues/119)). SourceKitten links the Swift runtime of the toolchain that built it, and Linux Swift has no stable ABI, so a prebuilt Linux binary only runs next to that exact toolchain. Elsewhere it either cannot find `libswiftCore.so` or crashes inside it. cdxgen's container images build sourcekitten against their own Swift toolchain instead. On other Linux hosts, build it from `thirdparty/sourcekitten` with the Swift toolchain you use for your projects and set `SOURCEKITTEN_CMD`. Without sourcekitten, cdxgen limits Swift evidence to import declarations.

## Limits

SourceKitten speaks to a SourceKit service matching the installed Swift toolchain, so a project using brand-new language features needs a binary built against a compatible Swift. The repackaged binaries pin one Swift version per release; if your project needs a newer one, build from `thirdparty/sourcekitten` against your toolchain and set `SOURCEKITTEN_CMD`.
