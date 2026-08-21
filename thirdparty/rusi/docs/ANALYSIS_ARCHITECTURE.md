# Rusi Analysis Architecture

This document describes how Rusi analyzes Rust code. It is written for two audiences.
Compiler engineers will find the intermediate representations, the call graph
resolution strategy, and the dataflow lattices described in enough detail to reason
about soundness and precision. Security analysts will find a precise account of what
the source-to-sink evidence means, how far it can be trusted, and where it stops.

The goal of the document is accuracy rather than advocacy. Where an algorithm is an
approximation, that is stated plainly, because a taint result is only useful to a
reviewer who knows its boundaries.

## 1. What Rusi is

Rusi is a static analysis engine for Rust projects. It produces a single deterministic
JSON report that combines structural evidence (packages, files, imports, declarations),
a call graph, interprocedural data flow with concrete source-to-sink slices, and
cryptography evidence suitable for CBOM style review. It is built to serve both security
review and ordinary program understanding, on the premise that both depend on the same
core, which is an accurate call graph and a defensible model of how values move through
a program.

Rusi runs in one of two backends that share one output schema.

The stable backend parses source with `syn` and performs a syntax and type-hint driven
analysis. It runs on stable Rust, does not execute the target, and is the default. It is
the fast and safe first pass.

The compiler backend embeds a `rustc` driver through `#![feature(rustc_private)]` and
analyzes the High-level IR (HIR) and Mid-level IR (MIR) that the real compiler produces.
It is higher fidelity because it works on type-resolved and monomorphized information, at
the cost of requiring the `rustc-dev` and `rust-src` components and a new enough `rustc`
(see `RUSTC_PRIVATE_VERSION_FLOOR`), and of running `cargo check` on the target. The
channel itself does not matter: on a non-nightly toolchain the wrapper is built with
`RUSTC_BOOTSTRAP=1`, which is how a release compiler is asked to accept an unstable
feature. Because a Cargo check
compiles build scripts and procedural macros, the compiler backend inherits Cargo build
time execution semantics, which is a trust consideration documented separately in the
threat model.

Both backends emit the same schema, defined in `crates/rusi-schema`. This is a
deliberate design choice. It lets the stable backend act as a fast approximation whose
gaps can be measured against the compiler backend acting as a higher precision oracle,
and it lets downstream consumers treat the two uniformly.

## 2. The shared schema and the canonical name join key

Every report carries tool and runtime metadata, workspace modules and packages, file
level evidence, flattened imports and declarations and usages and security signals, an
optional crypto section, an optional call graph, optional data flow evidence, and
summary statistics. Evidence is emitted once in canonical top level arrays, and each
item carries a file path and position so that a per file view can be reconstructed by
grouping. Output is minified by default and is byte for byte identical across repeated
runs on unchanged input, which matters both for review workflows and for regression
testing.

One element of the schema deserves special attention because it is central to Rusi's
intended role in a larger toolchain. Every function node carries a `canonical_name`.
This is a generic free, lifetime free, hash free reduction of the fully qualified Rust
name, of the shape `crate::module::Type::method`. The reduction strips trailing compiler
disambiguation hashes, removes LLVM thunk suffixes, reduces a trait qualified path such
as `<Type as Trait>::method` to the implementing type, and erases generic argument
groups so that every monomorphized instance collapses onto the single source definition
it came from. The purpose is to provide a stable join key between a source level call
graph produced by Rusi and a binary level call graph produced by a separate tool. A
consumer that wants to know whether a vulnerable symbol is reachable in a shipped binary
can match the two graphs on `canonical_name` without re-implementing Rust name
normalization. This is what makes Rusi useful beyond a single repository, and it is why
the normalization logic is part of the authoritative schema crate rather than a private
detail of either backend.

## 3. The stable backend

### 3.1 Parsing and the simplified IR

The stable backend begins from Cargo metadata to discover workspace packages, then walks
each package source tree and parses files with `syn`. A visitor lowers the syntax tree
into a small internal representation of expressions and operations. This representation
is intentionally lossy. It keeps the shapes that matter for call resolution and taint,
such as assignments, field assignments, method and function calls, and composition of
sub-expressions, and it discards detail that a syntax level analysis cannot use
soundly anyway. The representation records enough position information to materialize
reviewable traces later.

### 3.2 Call graph construction

The call graph is built from the calls observed syntactically in each function, resolved
against an index of the workspace's own functions and trait implementations. The
resolver is the part of the stable backend that received the most attention, because a
call graph that silently drops edges is worse than useless for reachability.

Resolution proceeds from most to least specific. A fully qualified or normalized path
that matches a single local function resolves directly and with high confidence. A
method call is resolved with the help of lightweight receiver type inference, which
tracks the declared or constructed type of local bindings so that a call on a value of a
known type prefers the implementation on that type. When the receiver type is known and
selects exactly one implementation, that edge is emitted as a receiver typed resolution.
When several candidates remain, the resolver does not give up and it does not guess a
single winner. It emits an edge to every candidate and marks the set as an
over-approximation with an explicit confidence and a candidate count, so that a consumer
can distinguish a proven edge from a set of possibilities. Trait method calls follow the
same principle. When the receiver type pins a single implementation the edge is exact,
and when it does not the resolver over-approximates to all implementations of the method
rather than dropping the call. Calls to closures passed into common combinators such as
`map`, `and_then`, and the spawning functions are connected to the closure body with a
dedicated higher order edge kind.

The design rule throughout is that a real local call is never rerouted to a synthetic
external node just because it is ambiguous. Over-approximation with a confidence label is
preferred to silent loss, because a security reviewer can filter a low confidence edge
but cannot recover an edge that was never emitted. The one honest limitation of the
stable backend is that it is syntax driven, so calls that live inside macro expansions
other than a small set of recognized ones, and calls through function pointers stored in
data, are not visible to it. These are exactly the cases the compiler backend exists to
cover.

### 3.3 The taint model

Taint in the stable backend is computed in two phases over a labeled origin domain.

The abstract domain associates each variable with a set of abstract origins, where an
origin is either a formal parameter of the enclosing function or a named source
category. This is not a single boolean. It is a set, so that a value can be understood as
carrying taint from several distinct sources at once, which is what allows the later
phase to attribute a finding to the correct originating source. Field accesses are
tracked to one level of precision, so that writing a tainted value into one field of a
struct does not by itself taint a sibling field. References, boxes, and the question mark
operator are treated as transparent, so taint follows through them.

The first phase computes a summary for every function through an interprocedural fixpoint.
A summary records which parameters flow to the return value, which parameters flow to
which sink categories, and which source categories a function returns. The fixpoint is
driven by a work list keyed on the caller relation, so that when a callee summary changes
only its callers are revisited. Summaries let the analysis reason about a call without
re-descending into the callee every time, which is what makes the interprocedural
analysis scale to real projects.

The second phase replays the analysis concretely inside each function to build witness
paths. Where the first phase asks whether a flow exists, the second phase reconstructs an
ordered chain of steps from a source, through assignments and passthroughs and calls, to
a sink, and records that chain as a slice. At a call the concrete phase consults the
precomputed summary rather than inlining the callee, and it stitches a synthetic step
that represents the parameter to return or parameter to sink relationship the summary
asserts. A reviewer therefore sees a coherent trace, with the understanding that the
interprocedural hops are summary derived rather than a full inlined walk.

### 3.4 Sources, sinks, sanitizers, and passthroughs

The security model is expressed as pattern packs of sources, sinks, sanitizers, and
passthroughs, and custom JSON packs can be merged with the built in modeling. The built
in packs cover environment, command line, file, and HTTP sources, and process execution,
filesystem mutation, network, SQL, and HTML response sinks, across the common Rust web
and database ecosystems.

Two aspects of the matching are worth stating precisely because they determine the false
positive and false negative behavior. Patterns are matched against callee text with path
segment awareness rather than a raw substring test, so that a pattern for a library
function does not accidentally fire on an unrelated user method whose name merely ends
with the same letters. Sanitization is scoped to the expression it applies to rather than
being treated as a statement wide switch, so that a parameterized query binding on one
value does not suppress an injection finding on a different concatenated string in the
same statement. Passthrough discovery, which lets taint follow through accessor style
methods that are not explicitly modeled, is gated on evidence that the method actually
forwards a parameter to its result, and a method that also matches a sanitizer is never
treated as a passthrough. These rules exist because the earlier and looser versions of
each produced either laundered taint or spurious findings, and the security value of the
tool depends on getting them right.

Certain aliasing situations are modeled explicitly and conservatively. Mutation through a
mutable reference parameter propagates taint into the referenced binding only when the
argument is actually passed by mutable reference, rather than smearing taint across every
argument of every multi argument call. Channel send and receive are modeled per channel,
keyed on the channel binding, rather than through a single global slot, so that two
independent channels do not cross contaminate.

## 4. The compiler backend

### 4.1 Structure

The compiler backend is a three stage pipeline. A driver detects toolchain capability,
builds the wrapper binary, and runs `cargo check` on the target under a Rust compiler
wrapper. The wrapper is a `rustc` driver that, in its after analysis callback,
walks the HIR and MIR of each crate compiled from the analysis root and writes a JSON
artifact of evidence. The driver then merges the per crate artifacts and reconciles them
with the stable evidence into a single report.

By default the wrapper only collects bodies for crates whose sources live under the
analysis root, so that analysis stays focused on the repository under review and does not
drown in generated or table heavy dependency code. A mode exists to widen collection to
dependency bodies where their MIR is available.

### 4.2 What is taken from HIR and from MIR

HIR provides declarations, imports, and the type resolved information at call sites, in
particular the receiver type and the resolved target of a method or function call, which
is where the precise dispatch typing lives. It also provides the classification of
closures and coroutines and the identification of unsafe blocks, and it is where crypto
material is recognized by binding name.

MIR provides the control flow and the operational detail. The wrapper lowers each MIR
body into a compact custom representation of basic blocks, assignments with their place
projections, and call terminators with their resolved targets and arguments. Working from
MIR rather than from source means the analysis sees the program after desugaring, so
patterns that are implicit in source, such as the operations behind operators and the
control flow behind combinators, are explicit.

### 4.3 A real MIR dataflow analysis

The compiler backend does not merely collect call edges. It runs two genuine fixpoint
dataflow passes over the reconstructed control flow graph. The abstract pass computes,
per basic block, a lattice of place to origin taint with set union as the join, and it
iterates to a fixpoint. The concrete pass materializes witness paths in the same way the
stable backend does, but over MIR places rather than syntactic variables, which gives it
access path precision keyed on locals and their projections rather than on names.
Interprocedural behavior is again summary based, computed bottom up over the call graph,
with summaries that capture parameter to return, parameter to sink, source to sink,
field return, and field write effects. These effect shapes are surfaced in the report so
that a reviewer can see not only that a function is relevant but in what way it moves
data.

### 4.4 Monomorphization aware call graph construction

The most significant precision feature of the compiler backend is that it resolves calls
through the same monomorphization information the compiler itself uses for code
generation, rather than through name matching.

The problem this solves is specific. In a generic function such as one that takes a value
of a type parameter bounded by a trait and calls a trait method on it, the callee cannot
be pinned by looking at that function alone, because the concrete implementation depends
on how the function is instantiated elsewhere in the program. A per body analysis, and
any purely syntactic analysis, sees only the abstract trait method.

Rusi's monomorphization pass walks the set of concrete function instances the crate
actually generates, obtained from the compiler's own collect and partition of mono items.
For each instance it takes that instance's MIR and, for every call terminator, applies
the instance's substitutions to the callee type and then resolves the callee to a
concrete instance. In the generic example, the instance for the function specialized to
one concrete type resolves the trait call to that type's implementation, and the instance
for another concrete type resolves it to the other implementation. Rusi unions the
concrete targets discovered across all instantiations of a given definition, which yields
a context insensitive but sound devirtualization. The abstract trait method call is
replaced in the authoritative call graph by edges to the concrete implementation methods,
each carrying the fact that it was resolved by devirtualization. The practical effect for
security is that taint now flows from a source, through a generic dispatch function, into
the concrete sink that the specialized implementation reaches, which a syntactic analysis
could never connect.

Calls that are genuinely virtual through a trait object are handled separately by
enumerating the trait's implementations, and calls that are intentionally modeled as
asynchronous or task boundaries, such as future polling and task spawning, are preserved
as logical edges rather than being devirtualized, because their value in the graph is the
boundary they represent.

### 4.5 Edge reconciliation

Because the compiler backend derives evidence from both HIR and MIR, and because the
monomorphization pass sharpens some edges, the same logical caller to callee relationship
can be produced more than once, and a stale edge to an abstract trait item can coexist
with the concrete edges that supersede it. A reconciliation step collapses duplicate
edges that share a source and target, keeping the one whose resolution is richest, and
drops an edge to an abstract trait item when the same caller already has a concrete edge
to an implementation of that method. This produces one coherent graph rather than a union
of two overlapping ones, and it is the first step toward a fuller reconciliation of the
two backends.

### 4.6 Native and foreign interfaces

Foreign function interfaces are recognized at two levels. Declarations of external
functions and statics are recorded as evidence with a native interop signal, and a set of
models describes the taint behavior of well known C library entry points so that a call
crossing into foreign code can still be reasoned about at the boundary. The foreign code
itself is not analyzed, so taint through a C body is modeled rather than proven, and this
is stated in the evidence confidence. Deeper cross language tracking, including parsing of
generated bindings and of native build inputs, is identified as future work rather than
claimed as present.

## 5. Cryptography evidence

Rusi emits crypto evidence intended for CBOM style review rather than protocol
verification. It records the crypto relevant libraries and namespaces that appear, the
concrete crypto API uses classified into algorithm and provider and kind and operation,
the secret like materials such as keys and nonces and salts identified without copying
their values, and review findings such as the use of weak primitives. A dedicated
analysis scope narrows the call graph and data flow to the crypto relevant sources, sinks,
and paths while preserving the crypto evidence section, which gives a reviewer a focused
view of how key material and secrets flow into cryptographic operations. The model is
classification oriented. It is good at recognizing common real world families and at
following secret material through ordinary method chains, and it does not claim to prove
that a protocol is correctly constructed.

## 6. What is novel here

The individual techniques, monomorphization driven call graph construction, access path
taint, summary based interprocedural analysis, are known in the program analysis
literature. What is distinctive about Rusi is the combination and the engineering stance.

It runs the same analysis intent through two backends of very different fidelity behind
one schema, which turns the fast and safe syntactic analysis and the slower and precise
compiler analysis into two points on a measurable precision curve rather than two
unrelated tools. It treats over-approximation with explicit confidence as the correct
response to ambiguity in a security tool, rather than either dropping edges or guessing,
so that recall is preserved and the consumer decides how much imprecision to tolerate. It
carries a canonical name that is designed as a join key to a binary call graph, which
positions the source analysis as one half of a reachability story that spans source and
shipped artifact. And it holds determinism and a stable schema as invariants, so that the
output is a dependable input to other tools rather than a report that shifts from run to
run.

## 7. Scope and honest limitations

The stable backend is syntax and type hint driven. It does not see through most macro
expansions and it cannot resolve calls through function pointers held in data. It is a
fast approximation and it is labeled as such.

The compiler backend is bounded by what a Cargo check exposes. It analyzes the crates
built from the analysis root, and it can only see dependency MIR where the compiler makes
it available, which for non generic dependency functions is often not the case. Its
interprocedural summaries are context insensitive, so a function's effect is unified
across its call sites. Its handling of some MIR constructs, in particular the suspension
points of coroutines and inline assembly, is partial, so taint that must pass through a
suspension relies on a reconstruction rather than a direct model.

Across both backends the analysis is sound leaning rather than sound in the formal sense.
Absence of a reported flow is not a proof that no flow exists, and a reported flow is a
well supported hypothesis backed by a concrete witness rather than a formal certificate.
The value of the tool is that it makes the supported hypotheses explicit, attributes them
to sources and sinks a reviewer can name, and shows the path, while being clear about the
places where its knowledge ends. That honesty is what lets a security analyst and a
compiler engineer trust the parts that are strong and compensate for the parts that are
approximate.
