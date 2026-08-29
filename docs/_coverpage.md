# cdxgen-plugins-bin

> The native half of cdxgen. Semantic analyzers, trust inspectors, and BOM accelerators, shipped as statically linked binaries.

[Architecture](ARCHITECTURE.md) · [Lessons](LESSON1.md) · [Tool guides](README.md)

```mermaid
graph LR
  A[cdxgen] --> B{Scan needs}
  B -->|Go source| C[golem]
  B -->|Rust source| D[rusi]
  B -->|container or rootfs| E[trivy-cdxgen]
  B -->|Swift| F[sourcekitten]
  B -->|.NET| G[dosai]
  B -->|live OS| H[osquery]
  B -->|trust posture| I[trustinspector]
  B -->|validate or fetch| J[cdxrs]
  B -->|explore a BOM| K[cdxui]
```

Nine helpers, one contract: take a project or a host, return compact JSON a Node.js process can merge into a CycloneDX document.
