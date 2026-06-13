# cdxui

A Rust terminal user interface for exploring CycloneDX Software Bill of Materials (SBOM) files. cdxui provides interactive browsing, searching, and filtering of BOM data including components, cryptographic assets, services, formulations, and dependency trees.

cdxui can load pre-generated BOM files or spawn cdxgen to generate a BOM live, displaying the generation logs, reasoning traces, and activity indicators.

## Features

- Load CycloneDX JSON BOM files (versions 1.4 through 2.0) from a single file or directory
- Live BOM generation by spawning cdxgen with argument forwarding
- Seven tabbed views: Logs, Summary, Components, Crypto, Services, Formulation, Dependencies
- Full-text search across all component fields with type filtering
- Sortable component tables with column cycling
- Detail panel showing licenses, properties, evidence, hashes, external references, and cryptographic properties
- Expandable/collapsible dependency trees with cycle detection
- Interactive formulation viewer with workflow and task hierarchy
- Live log streaming with thought panel (CDXGEN_THINK_MODE) and trace activity indicators (CDXGEN_TRACE_MODE)
- License distribution bar chart in Summary view
- Component merging across multiple BOM files by purl or bom-ref
- Property value newline splitting for cdxgen namespace properties
- Mouse wheel scroll and keyboard panel scrolling
- Dark and light themes

## Installation

```bash
cargo build --release
```

The binary is at `target/release/cdxui`.

## Usage

### View an existing BOM

```bash
cdxui path/to/bom.json
cdxui path/to/bom-directory/
```

### Live generation with cdxgen

```bash
CDXGEN_CMD="cdxgen" \
CDXGEN_ARGS="-t pnpm --no-recurse -o /tmp/bom.json /path/to/project" \
cdxui --generate

# With FETCH_LICENSE for rich trace activity
FETCH_LICENSE=true CDXGEN_CMD="cdxgen" \
CDXGEN_ARGS="-t pnpm --no-recurse -o /tmp/bom.json /path/to/project" \
cdxui --generate
```

When run with `--generate`, cdxui spawns cdxgen with `CDXGEN_THINK_MODE=true`, `CDXGEN_TRACE_MODE=true`, and file-based logging for thoughts and traces. The Logs tab shows live stdout with a separate thoughts panel. After generation completes, the output BOM is loaded automatically and the view switches to the Summary tab after a short delay.

### CLI arguments

```
cdxui [OPTIONS] [PATH]

Arguments:
  [PATH]  Path to a CycloneDX BOM file (.json) or directory

Options:
  --generate            Spawn cdxgen for live BOM generation
  --output <PATH>       Output BOM path for generate mode [default: /tmp/bom.json]
  --no-alternate-screen Skip alternate screen (debugging)
  --theme <THEME>       Color theme: dark, light [default: dark]
```

### Environment variables

`CDXGEN_CMD` specifies the cdxgen binary or script path. Defaults to `cdxgen`. Use `node /path/to/cdxgen/bin/cdxgen.js` when running from source.

`CDXGEN_ARGS` forwards arguments to cdxgen during generation mode. Example: `-t pnpm --no-recurse -o /tmp/bom.json /path/to/project`.

`FETCH_LICENSE` set to `true` enables license fetching during generation, generating trace events for testing the activity indicator.

## Keyboard shortcuts

| Key                              | Action                                                         |
| -------------------------------- | -------------------------------------------------------------- |
| `0`-`6`                          | Switch to tab by number                                        |
| `Tab` / `Shift+Tab`              | Next/previous tab                                              |
| `Up`/`Down` or `j`/`k`           | Move selection                                                 |
| `Ctrl+Up`/`Ctrl+Down`            | Scroll panel without moving selection                          |
| `Space` / `b`                    | Page down / page up                                            |
| `g` / `G`                        | Go to top / bottom                                             |
| `Enter`                          | Toggle detail panel (or expand dependency node in Summary tab) |
| `/`                              | Focus search bar                                               |
| `Esc`                            | Clear search                                                   |
| `f`                              | Filter by component type                                       |
| `s`                              | Cycle sort column                                              |
| `Space` (on Deps/Summary)        | Toggle expand/collapse of selected dependency node             |
| `Left`/`Right` (on Deps/Summary) | Collapse/expand selected dependency node                       |
| `+`/`-` (on Deps/Summary)        | Expand all / collapse all dependency nodes                     |
| `q`                              | Quit                                                           |

Mouse wheel scrolls panels vertically.
