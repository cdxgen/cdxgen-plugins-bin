# Lesson 9: Flows that only a fixpoint finds, in rusi

## Learning objective

Understand, by running it, why a data-flow analysis must run to convergence: what a loop-carried or recursion-carried flow looks like in a rusi report, why a cap on iteration rounds is a silent false negative, and how an analyzer can be made both unbounded in depth and cheap in practice.

## Pre-requisites

- [Lesson 3](LESSON3.md), with rusi built:

```bash
cd thirdparty/rusi
cargo build --release -p rusi-cli
```

## The failure a round cap hides

A data-flow analysis computes facts by repeatedly re-reading every function until the facts stop changing: a fixpoint. The tempting shortcut is to stop after N rounds, because real code converges in two or three. rusi carried exactly those caps for a while, and each one cut off a real class of flow:

- the stable backend's summary pass stopped after six rounds, and each round moved a summary one call up the chain, so any source-to-sink chain seven functions deep was silently dropped
- the compiler backend stopped after eight rounds, losing chains nine deep
- its per-function block passes stopped after 64 rounds, losing a value carried 63 times around a loop
- worst, the stable backend lowered loops as plain straight-line operations, so the loop handling existed but was never reached, and every loop-carried flow was lost, even one trip deep

On the fixture this lesson uses, the stable backend found 4 of its 13 environment flows before the fix. Nothing errored, nothing logged; the flows were simply absent. That is the character of the bug class: an analysis that stops early does not report worse results, it reports fewer, and only a fixture that needs the depth can tell you.

## Run the fixture

`fixtures/fixpoint-flow-app` was written to pin the property. It holds twelve-deep call chains in both directions, values that only reach a sink after a trip around a `for`, `while` or `loop`, nested loops, one seventy-step chain, self and mutual recursion, and a trait object with forty implementations:

```bash
target/release/rusi analyze --dir fixtures/fixpoint-flow-app \
  --dataflow security --out /tmp/fixpoint.json
jq '.dataFlow.flows | length' /tmp/fixpoint.json
```

The fixture's `expected.jsonl` lists every flow the analysis owes: 69 of them across environment sources and the parameter carriers of the dispatch targets. Diff your run against it:

```bash
jq -r '.dataFlow.flows[] | [.source.category, .sink.category, .source.function] | @tsv' /tmp/fixpoint.json | sort
grep -o '"source_category": "[^"]*".*"sink_category": "[^"]*"' fixtures/fixpoint-flow-app/expected.jsonl | sort
```

Both backends report the full set, because neither limits how many rounds its fixpoints run. Depth costs time, never findings.

## Read a loop-carried flow

The fixture's `carried_by_for` is four lines and worth reading slowly:

```rust
let mut current = String::new();
let mut next = String::new();
for _ in 0..3 {
    current = next.clone();
    next = std::env::var("FOR_INPUT").unwrap_or_default();
}
let _ = Command::new(current).status();
```

At the sink, `current` holds a value `next` had at the end of the previous trip, and `next` holds the environment read. No single pass through the body can see that; the second trip can, and the analysis only terminates after it re-walks the body from the state the first trip left behind, folding each trip's end state back into the loop's head until a trip adds nothing. Then, and only then, one final walk records the slice. Nothing is emitted while the loop settles, which is why a call site taint reaches only after a trip is still counted exactly once.

## Why unbounded does not mean slow

Running to convergence sounds expensive. Three scheduling choices make it cheap, and they live in one shared module both backends use:

- Every item, block or function, has a rank in dataflow order, and the worklist always serves the lowest-ranked dirty item. When a back edge dirties a loop head, the traversal returns to it at once instead of first re-running later code on input that is about to change. Loop-free input finishes in one pass. rustc adopted the same traversal for its own MIR dataflow.
- Blocks are ranked in a weak topological order rather than plain reverse postorder, so every loop is one contiguous run of ranks right after its head. Loops settle innermost first, whatever order a block lists its successors in.
- Functions are ranked callees first, leaves of the call graph ahead of their callers, with recursion cycles kept together. The stable backend evaluates a whole level in parallel, since nothing on one level calls anything else on it. A chain twenty functions deep takes twenty evaluations, not twenty rounds over everything.

Each evaluation records which summaries it read, and a summary that grows re-dirties exactly its readers, so correctness does not depend on the schedule guessing the graph shape right. And a nested loop resumes from the head it settled on rather than starting over, so a nest sixteen deep costs the sum of its fixpoints rather than their product: a loop whose head can hold F name and origin pairs is walked at most F + 2 times, however deep the nest.

Termination needs one honest widening. A function that recurses on a field of its own parameter, `walk(&node.next)`, would grow `n.next.val`, then `n.next.next.val`, forever if the summary kept extending the place. Inside a recursion cycle the summary rebases such a place onto the argument alone, which only coarsens, and that is the only widening either backend applies. Everything else terminates because states are finite: an item is revisited only when a join strictly added to it.

A witness, once found, is kept whole however long it is. The fixture's seventy-step chain produces a witness with 71 edges, and no origin ever loses its witness to a length cap.

## The compiler backend agrees

The same worklists serve the compiler backend, whose MIR passes face the same two levels, blocks within a function and functions across the call graph:

```bash
rustup toolchain install nightly
target/release/rusi analyze --dir fixtures/fixpoint-flow-app \
  --backend compiler --toolchain nightly \
  --dataflow security --out /tmp/fixpoint-compiler.json
```

The first run builds the embedded rustc wrapper on your machine, optimized, so it takes longer than later runs. `--toolchain auto` also works when only a dated nightly is installed, as CI pins are, because it names that nightly in full rather than reaching for a rolling channel you do not have.

## Depth of another kind: the stack

Recursion in the analyzer itself is a depth question. Parsing and lowering walk expressions recursively, so the stack decides how deeply nested an expression rusi can take. Analysis runs on threads with 16 MiB of stack, the same size rustc runs its own compiler with, and `RUST_MIN_STACK` overrides it. The fixture `fixtures/deep-nesting-app` holds expressions nested 800 deep, the shape of generated tables and parsers; rustc compiles them, and so does rusi:

```bash
target/release/rusi analyze --dir fixtures/deep-nesting-app --out /tmp/deep.json
```

Before the fix, a release build died of a stack overflow on that input and the whole run and its evidence were lost. The lesson generalizes: when your tool's input is code, your tool's resource limits should be measured against the compiler's, because generated code will find the gap.

## What you learned

- a round cap is a silent false negative, and the fixture that exposes it has to be as deep as the behavior you claim
- convergence is made affordable by scheduling: lowest-rank-first worklists, weak topological order, callees first with read tracking
- loops are walked until a trip adds nothing, nested loops resume from settled heads, and slices are recorded only from the fixpoint
- the one widening is rebasing a recursive summary place onto its argument; witnesses are never truncated
- stack limits belong in the same conversation, benchmarked against what the compiler itself accepts

Next: [Lesson 10, where each helper's own SBOM comes from](LESSON10.md).
