# cdxgen-plugins-bin

> Native helper binaries that supercharge cdxgen: semantic analyzers, trust inspectors, and BOM accelerators for Go, Rust, Swift, .NET, and containers.

[Architecture](ARCHITECTURE.md) · [Lessons](LESSON1.md) · [golem](GOLEM.md) · [rusi](RUSI.md) · [cdxrs](CDXRS.md)

Every binary in this repository exists because cdxgen, a Node.js application, meets a wall that only native tooling can climb: Go SSA and type resolution, Rust synthesis and MIR evidence, Swift SourceKit, .NET assembly reflection, OS package databases, keyrings, and code-signing APIs. cdxgen ships the wall-climbing gear here, one statically linked helper per job, and calls it when your scan needs it.

## What lives here

| Helper         | Language | Job                                                             |
| -------------- | -------- | --------------------------------------------------------------- |
| golem          | Go       | Go source evidence, call graphs, data flow, API endpoints, CBOM |
| rusi           | Rust     | Rust source evidence, call graphs, data flow, crypto inventory  |
| cdxrs          | Rust     | Fast BOM validation and registry metadata fetch                 |
| cdxui          | Rust     | Terminal UI for exploring and generating BOMs                   |
| trustinspector | Go       | Trust anchors, code signing, notarization, WDAC, Gatekeeper     |
| trivy-cdxgen   | Go       | Container and rootfs OS package inventory                       |
| sourcekitten   | Swift    | Swift semantic analysis via SourceKit                           |
| dosai          | C#       | .NET assembly and source inspection                             |
| osquery        | C++      | Live operating system instrumentation for OBOM                  |

## Start here

- [What this repository is](README.md)
- [How cdxgen finds and runs these binaries](ARCHITECTURE.md)
- [Building and publishing](BUILD.md)

## Tool guides

- [golem: Go Library Evidence Mapper](GOLEM.md)
- [rusi: Rust Source Inspector](RUSI.md)
- [cdxrs: Rust-native BOM validation and fetch](CDXRS.md)
- [cdxui: terminal BOM explorer](CDXUI.md)
- [trustinspector: trust posture inspection](TRUSTINSPECTOR.md)
- [Bundled upstream helpers](HELPERS.md)

## Lessons

1. [First Go evidence report with golem](LESSON1.md)
2. [Go call graphs, reachability, and data flow](LESSON2.md)
3. [Rust evidence with rusi](LESSON3.md)
4. [Exploring BOMs with cdxui](LESSON4.md)
5. [BOM validation with cdxrs](LESSON5.md)
6. [Trust posture with trustinspector](LESSON6.md)
7. [Build, package, and publish the binaries](LESSON7.md)
