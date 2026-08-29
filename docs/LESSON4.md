# Lesson 4: Exploring BOMs with cdxui

## Learning objective

Use cdxui to inspect an existing CycloneDX BOM, then generate a new one from inside the terminal while watching cdxgen's reasoning traces live.

## Pre-requisites

- cdxui built: `cd thirdparty/cdxui && cargo build --release`
- a BOM file; generate one first if you do not have a spare:

```bash
npm install -g @cyclonedx/cdxgen
cdxgen -t nodejs -o /tmp/bom.json /path/to/any/js/project
```

## Open a BOM

```bash
thirdparty/cdxui/target/release/cdxui /tmp/bom.json
```

Eight tabs cover the document: Logs, Summary, Vulnerabilities, Components, Crypto, Services, Formulation, and Dependencies. A few minutes with the arrow keys teaches the layout faster than any prose, but here is the map of where questions live:

| Question                                           | Tab          |
| -------------------------------------------------- | ------------ |
| What is in this BOM, at a glance?                  | Summary      |
| Which components carry licenses, hashes, evidence? | Components   |
| What cryptographic assets did the scan find?       | Crypto       |
| What services does the application expose?         | Services     |
| How was this artifact built?                       | Formulation  |
| Where does this component sit in the tree?         | Dependencies |

Search is full-text across component fields, with type filters and column sorting. The detail panel shows licenses, properties, evidence, hashes, and external references for whatever row is selected. Dependency trees expand and collapse and flag cycles instead of recursing into them forever.

Point cdxui at a directory instead of a file and it merges every BOM it finds by purl or bom-ref, which makes it a decent reviewer for a directory of per-service BOMs:

```bash
cdxui ./boms/
```

VDR and VEX documents from OWASP dep-scan render in the Vulnerabilities tab, so a triage session does not need a second tool:

```bash
dep-scan /path/to/project
cdxui ./sbom-project.vdr.json
```

## Generate a BOM live

The second mode is more interesting. Instead of loading a finished BOM, cdxui spawns cdxgen and streams its work:

```bash
CDXGEN_CMD="cdxgen" \
CDXGEN_ARGS="-t nodejs --no-recurse -o /tmp/bom.json /path/to/project" \
cdxui --generate
```

Under the hood cdxui sets `CDXGEN_THINK_MODE=true`, `CDXGEN_TRACE_MODE=true`, and file-based logging. The Logs tab streams stdout. A thought panel shows the model's reasoning when think mode emits it. Trace activity indicators light up as each stage runs. When cdxgen exits, the BOM at the path in `CDXGEN_ARGS` loads automatically and the view jumps to Summary.

Why watch? Because when a BOM is missing something, the useful question is what the generator did. Was the project type detected? Did the license fetch run? Did a stage time out? Watching one generation answers in a minute what a dozen log greps would.

`FETCH_LICENSE=true` enriches the trace activity, since license fetching is one of the slowest and most visible stages:

```bash
FETCH_LICENSE=true CDXGEN_CMD="cdxgen" \
CDXGEN_ARGS="-t nodejs -o /tmp/bom.json /path/to/project" \
cdxui --generate
```

## When to reach for cdxui

Reach for it during review, triage, and demos: any moment a human is asking questions of a BOM. Reach for `jq`, CycloneDX libraries, or dep-scan when a machine is asking. cdxui reads documents and shows you cdxgen at work; it does not edit BOMs or replace your pipeline.
