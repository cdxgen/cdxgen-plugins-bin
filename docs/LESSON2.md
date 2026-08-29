# Lesson 2: Go call graphs, reachability, endpoints, and crypto with golem

## Learning objective

Move beyond structure evidence into analysis: build call graphs in different modes, use root selection to make a library analyzable, read reachability and collapsed edges, extract enriched API endpoints, and generate CBOM-grade crypto findings.

## Pre-requisites

- golem built as in [Lesson 1](LESSON1.md)
- a Go module with an HTTP server or a library entry point; golem's own test fixtures work well

## Call graph modes and when each is right

```bash
/tmp/golem analyze --dir thirdparty/golem --callgraph static --out /tmp/cg-static.json
/tmp/golem analyze --dir thirdparty/golem --callgraph cha    --out /tmp/cg-cha.json
/tmp/golem analyze --dir thirdparty/golem --callgraph rta    --out /tmp/cg-rta.json
/tmp/golem analyze --dir thirdparty/golem --callgraph auto   --out /tmp/cg-auto.json
jq '.callGraph.stats' /tmp/cg-static.json /tmp/cg-cha.json /tmp/cg-rta.json /tmp/cg-auto.json
```

The progression is precision against cost. `static` is deterministic and misses dynamic dispatch. `cha` assumes any interface method can reach any implementation, so it over-approximates. `rta` starts from roots and keeps only reachable code. `vta` refines through variable type analysis. `auto` chains them, falling back on timeout, and records which algorithm actually ran in `callGraph.diagnostics`.

## Root selection makes libraries analyzable

This is the switch people miss. With default roots (`main`), a module with no `main` package yields almost nothing, because nothing is reachable from nothing:

```bash
/tmp/golem analyze --dir thirdparty/golem/internal/analyzer --roots exported --out /tmp/lib.json
jq '.callGraph.stats' /tmp/lib.json
```

`exported` seeds every exported function, which turns a library into a graph with real reachability from its public API. Other root modes: `init`, `tests`, `handlers`, `all`, and `symbol:<regex>` for anything matching a pattern.

## Reachability and witness paths

`callGraph.reachability` answers, per node, whether any root reaches it (`reachableFromRoots`), how far (`minDepth`), and from which roots. For named symbols you can also ask for witness paths:

```bash
cat > /tmp/symbols.txt <<'EOF'
endpointFactsForPackage
classifyEndpointCall
EOF
/tmp/golem analyze --dir thirdparty/golem --roots exported \
  --reachable-symbols /tmp/symbols.txt --max-paths-per-symbol 3 --out /tmp/paths.json
jq '[.callGraph.reachability.nodes[] | select(.reachableFromRoots)] | length' /tmp/paths.json
jq -c '.callGraph.reachability.paths[] | {symbol, depth}' /tmp/paths.json
```

## Filtering is a view

Exclude the standard library and dependency interiors, and long paths through omitted code survive as single `collapsed` edges carrying hop counts and the packages traversed:

```bash
/tmp/golem analyze --dir thirdparty/golem --callgraph rta \
  --dependency-detail collapse --out /tmp/view.json
jq '[.callGraph.edges[] | select(.collapsed == true)] | length' /tmp/view.json
```

That edge shape matters for reachability consumers: a handler invoked through `net/http` still has an edge from the code that registered it, with the traversal recorded rather than severed.

Export the graph for the tool of your choice:

```bash
/tmp/golem analyze --dir thirdparty/golem --callgraph rta --format graphml --out /tmp/cg.graphml
```

## Enriched API endpoints

Point golem at a service that registers routes. The analyzer's own `endpoints-gin` fixture is a compact example: a small Gin service whose handlers exercise every enrichment feature:

```bash
/tmp/golem analyze --dir thirdparty/golem/testdata/endpoints-gin --out /tmp/api.json
jq -r '.apiEndpoints[] | [.method, .path, .handler] | @tsv' /tmp/api.json
```

Group prefixes are already composed, including the group-root idiom `users.GET("", listUsers)`, which appears as `GET /api/v1/users`. Now the signatures:

```bash
jq '.apiEndpoints[] | select(.path == "/api/v1/users/:id") | {parameters, responseType}' /tmp/api.json
jq '.apiEndpoints[] | select(.path == "/api/v1/users" and .method == "POST") | {requestBodyType, responseType}' /tmp/api.json
```

The first shows a path parameter `id` extracted from `c.Param("id")` and a `User` response from `c.JSON`. The second shows a `CreateUserRequest` request body from `c.ShouldBindJSON(&req)`, with the handler's `AbortWithStatusJSON` error path correctly not promoted to the response type. An error-only handler, one whose every emitter is a 4xx, keeps the error shape instead of reporting nothing.

The same extraction covers chi (including `chi/v5` module paths), Echo, and plain net/http services using `r.PathValue` and the `json` codec pair. Matching resolves package paths and parameter types, so an import alias or a context parameter named `ctx` does not break it. When the analyzer cannot be confident, the field stays empty; that is deliberate, because downstream schema generation turns a guessed type into a wrong API contract.

## Crypto evidence for CBOM

```bash
jq '.crypto.libraries, .crypto.findings' /tmp/api.json
```

On a project that uses `crypto/md5` or `crypto/tls` with `InsecureSkipVerify: true`, findings appear with severity and confidence. The `confidence` field separates type-resolved evidence from name-based indicators; treat the first as fact and the second as a lead.

```bash
/tmp/golem analyze --dir /path/to/service --dataflow crypto --out /tmp/cbom-evidence.json
```

Data-flow mode `crypto` tracks key material into crypto APIs, which is the evidence a CBOM consumer wants: not just "this project imports sha2" but "this function passes this value into this key derivation call".

## What you learned

- call graph modes are a precision dial; `auto` is a sensible default and `exported` roots rescue libraries
- reachability is computed on the complete graph, then filtered as a view, so exclusions never silently sever paths
- endpoints carry handler signatures with a confidence discipline: empty beats wrong
- crypto findings distinguish resolved evidence from name matches

Next: [Lesson 3, Rust evidence with rusi](LESSON3.md).
