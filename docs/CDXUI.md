# cdxui: terminal BOM explorer

cdxui is a Rust terminal UI for CycloneDX BOM files. It loads one BOM, a directory of BOMs, or a VDR/VEX document; it renders the data in tabbed, searchable, keyboard-driven views; and it can spawn cdxgen to generate a BOM live while showing the generation logs and reasoning traces.

## Install

```bash
cd thirdparty/cdxui
cargo build --release
target/release/cdxui --help
```

## Explore an existing BOM

```bash
cdxui path/to/bom.json
cdxui path/to/bom-directory/
cdxui path/to/sbom.vdr.json     # VDR or VEX from OWASP dep-scan
```

CycloneDX 1.4 through 2.0 are supported. Multiple files merge by purl or bom-ref, so pointing cdxui at a directory gives you one deduplicated view over all of them.

The eight tabs cover the useful surface of a BOM: Logs, Summary, Vulnerabilities, Components, Crypto, Services, Formulation, and Dependencies. Components support full-text search, type filtering, and column-sortable tables. The detail panel shows licenses, properties, evidence, hashes, external references, and cryptographic properties. Dependency trees expand and collapse with cycle detection, and the formulation tab renders workflow and task hierarchy for BOMs that carry build provenance.

## Generate a BOM live

```bash
CDXGEN_CMD="cdxgen" \
CDXGEN_ARGS="-t pnpm --no-recurse -o /tmp/bom.json /path/to/project" \
cdxui --generate
```

With `--generate`, cdxui spawns cdxgen with `CDXGEN_THINK_MODE=true`, `CDXGEN_TRACE_MODE=true`, and file-based logging enabled. The Logs tab streams stdout while a separate panel shows the model's thoughts and another shows trace activity as it happens. When generation finishes, the output BOM loads automatically and the view switches to Summary.

That combination turns BOM generation from a black box into a walkthrough: you watch what cdxgen decided, in order, with the reasoning attached, and the artifact lands where `CDXGEN_ARGS` pointed.

## Keyboard-first

Everything is reachable from the keyboard: tab switching, search, sorting, tree expansion, panel scrolling. Mouse wheel scrolling works where the terminal supports it. Dark and light themes follow the terminal.

## When cdxui is the right tool

Use it when you want to answer questions about a BOM rather than about a codebase: what did this scan actually find, why is this component here, what evidence attached to it, what does the dependency tree look like around this cycle. For programmatic questions, use `jq` on the BOM; for human questions during review or a demo, cdxui is faster than any editor.
