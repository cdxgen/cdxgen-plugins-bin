# dosai: .NET source and assembly inspection

[dosai](https://github.com/owasp-dep-scan/dosai), the Dotnet Source and Assembly Inspector from the OWASP dep-scan project, lists namespaces and methods from .NET sources and compiled assemblies. It is the .NET counterpart of sourcekitten: a native inspector that gives cdxgen language semantics the JavaScript runtime cannot provide. The [official dosai documentation](https://owasp-dep-scan.github.io/dosai/) covers the tool in full, including its CLI and release notes.

The binaries are repackaged upstream release artifacts, downloaded and hashed by `scripts/thirdparty-downloads.sh`. cdxgen invokes dosai for .NET project scans when the binary is present; a custom build can be wired in with `DOSAI_CMD`.

## What it inspects

dosai works on both halves of a .NET codebase. On source trees it reads C# and related sources and reports the namespaces and methods they declare. On compiled artifacts it loads `.dll` and `.exe` assemblies and reports the same through reflection, which is what makes it useful for applications that ship prebuilt assemblies, vendor drop-ins, or a mix of source and binaries.

For cdxgen this means .NET BOMs can enumerate dependencies through source analysis and assembly inspection rather than only through lock files, and evidence about which namespaces and methods a component contributes can attach to the BOM the way golem evidence does for Go.

## Direct usage

The [official documentation](https://owasp-dep-scan.github.io/dosai/) documents the full CLI. The typical shapes:

```bash
dosai --dirs ./src
dosai --assemblies ./artifacts/MyApp.dll
```

Point it at source directories, assembly files, or both, and it prints namespace and method inventory as JSON.

## Platforms

linux-amd64, linux-arm, linux-arm64, linuxmusl-amd64, linuxmusl-arm64, darwin-amd64, darwin-arm64, windows-amd64, and windows-arm64.

## Relationship to cdxgen

cdxgen already parses .NET project files and lock files on its own. dosai is called when deeper evidence is needed: resolving what an assembly actually contains, or connecting source-level declarations to the components in the BOM. If the binary is missing, cdxgen falls back to manifest-only .NET analysis and the scan still succeeds.
