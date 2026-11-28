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

Both backends spell a path the same way, from the package's name, as
`package::module::item`, whichever target of the package the item sits in, so a binary
target `rusi` of the package `rusi-cli` is `rusi_cli::...` in either, and `package_path`
is that name too. rustc prints paths into the crate it is compiling with no crate segment
at all, so the compiler backend spells each such path from the package, including the ones
inside `<Type as Trait>`. Its `qualified_name` keeps the trait an impl method implements
(`<pkg::Stage01 as pkg::Stage>::apply`) where the stable backend writes
`pkg::Stage01::apply`, and the two agree on `canonical_name`. When both backends report,
the compiler's declaration of an item takes the place of the stable one with the same
package, file, canonical name and line, since the call graph the report then carries is
the compiler's and names its nodes by the compiler's ids; it keeps the stable
declaration's cfg gate, because the compiler only sees code that survived cfg expansion.

## 3. The stable backend

### 3.1 Parsing and the simplified IR

The stable backend begins from Cargo metadata to discover workspace packages. Module
discovery then reads every source file once and parses it once, and that single parse
does three jobs: it walks the `mod` declarations from each crate root to establish what
each file is and where it sits, it collects the `macro_rules!` definitions, module
declarations and `use` items the macro pre-pass needs (section 3.5), and it leaves the
file's text in memory for the analysis pass, so no file is read from disk twice. The
per-file work runs as tasks on one worker pool shared by every package, so the walk of
a package with a single huge crate does not serialize the front of the pipeline behind
it; the traversal decisions, the notes, and the order of everything they produce are
replayed in the order a sequential walk would have recorded. A visitor then parses the
text a second time and lowers the syntax tree into a small internal representation of
expressions and operations. Two parses and one read per file
is the deliberate floor: keeping parsed trees across passes is not possible with `syn`
spans, which hold `Rc` and cannot cross a thread boundary, and keeping every tree would
cost an order of magnitude more memory than the text does. The lowering representation
is intentionally lossy. It keeps the shapes that matter for call resolution and taint,
such as assignments, field assignments, method and function calls, and composition of
sub-expressions, and it discards detail that a syntax level analysis cannot use
soundly anyway. The representation records enough position information to materialize
reviewable traces later. How many files each front-of-pipeline phase actually read and
parsed is counted in the `file_work` section of the `--stats-json` document, so the
"parsed at most twice" bound is checked on every run rather than asserted.

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
but cannot recover an edge that was never emitted. For declarative macros the stable
backend runs its own expander: a pre-pass collects every `macro_rules!` definition in the
analyzed crates with its scoping (textual, path-based through `use`, exported at the
crate root, hoisted by `#[macro_use] mod`), each workspace invocation is matched and
transcribed, and the result is walked like hand-written code, with every item it
produces stamped `expanded_from` and positioned at the invocation site. Calls to
dependency macros become `macro-call` usages and `macro` edges that name the owning
crate. The one honest limitation that remains is that it is syntax driven, so calls that
live inside dependency macro expansions (their source is only read under `--deps`),
inside procedural macros, and through function pointers stored in data, are not visible
to it. These are exactly the cases the compiler backend exists to cover.

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
which sink categories, and which source categories a function returns. Functions are
evaluated callees first, one call graph level at a time and in parallel within a level,
and every evaluation records the summaries it read, so that when a summary grows exactly
the functions that looked at it are revisited. A call chain of any depth settles in one
pass; only recursion is iterated. Section 5 describes the schedule and why it needs no
round limit. Summaries let the analysis reason about a call without re-descending into
the callee every time, which is what makes the interprocedural analysis scale to real
projects.

Within a function the operations are kept in source order, and each `for`, `while` and
`loop` body is recorded as a region of them. Both phases walk a region repeatedly from
the state at its head, folding the state each trip ends in back into the head, until a
trip adds nothing. That is what lets a value assigned late in a loop body reach a use
earlier in the body on the next trip, and it is also what holds after the loop, since a
loop may run any number of times. A nested loop keeps the head it settled on, so the next
trip of the loop around it resumes from there rather than starting over. Nothing is
reported while a loop settles: the body is then walked once more from the settled head,
and that walk is the one that records slices. Section 5 gives the bound on the walks.

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

### 3.5 Declarative macros

The stable backend expands the `macro_rules!` macros of the analyzed workspace itself.
The code lives in `crates/rusi-core/src/macro_expand/`, one file per concern.

`scope.rs` runs before any file is analyzed. Its items are collected from the same
parse module discovery makes (section 3.1): every definition with its position and the
module declarations, `use` items and `extern crate` items that decide where each one is
visible. The scope table itself is built from those items before the first file is
analyzed, and it answers one question: what does the macro path written at this
position mean? Textual scope follows the Rust Reference: a definition is visible
from its position to the end of its module and in child modules declared after it, never
past the block that holds it, and a later definition of the same name shadows an earlier
one by line and column. `#[macro_use]` on a `mod` item extends that scope past the item,
through every level that carries it. Path-based scope comes from `#[macro_export]` (an
item of the crate root, whatever module defines it) and from `use` items, which are
followed to a fixed point through globs, aliases, `self::`, `super::`, `crate::` and the
exported macros of other workspace crates. `#[macro_use] extern crate c;` of a workspace
crate expands `c`'s macros; of a dependency, it attributes the call to the dependency, or
records the candidates when more than one such crate could supply the name. Each
definition becomes a `kind: "macro"` declaration.

`matcher.rs` follows rustc's matcher: the pattern is compiled to a list of positions, all
live positions advance over the invocation one token at a time, and a fragment specifier
is parsed (with `syn`) only when exactly one position waits for it. Two positions waiting
for a fragment, or one waiting for a fragment next to one waiting for a literal token, is
the local ambiguity rustc rejects, so rusi reports it instead of guessing. A token is
what rustc reads as one token: `+=`, `::`, `=>` and `'a` are single tokens for `tt`, for
separators and for literal tokens in a pattern. `transcriber.rs` substitutes the bindings,
keeps a multi-token `expr` binding grouped so `$e * 2` does not re-associate, and rewrites
`$crate` to `crate`, or to the defining crate's name when the invocation is in another
crate. `hygiene.rs` gives each binding the transcriber writes (`let`, `if let`,
`while let`, `for`, closure parameters, `match` arms, tuple and struct patterns, inline
format arguments) a suffix that is unique to the invocation, so it cannot alias a caller
variable of the same name; names after `::` or `.`, struct fields and keys, macro names,
item names and types are not renamed, and the suffix is removed from the report before it
is returned.

A workspace macro invoked in expression position (`let v = get!();`, an argument, a
tail, an initializer, an argument of `format!`) is expanded before the statement around
it is lowered, and its expansion is the value of the invocation, so a source read inside
the macro keeps its flow into a sink outside it. The walk then reuses that expansion
instead of expanding again.

The result is parsed for the invocation's position (statements inside a function, items
outside one, otherwise an expression) and walked by the same collector as hand-written
code. Everything it produces is positioned at the invocation site and carries
`expanded_from`; evidence ids and closure names include the invocation site and a
per-file expansion number, so two invocations of one macro never merge.

Four bounds keep an expansion finite, each with its own `macro` diagnostic: a nesting
depth of 128 expansions (rustc's default, raised to the crate's
`#![recursion_limit]` up to 256), a budget of 50,000 transcribed tokens for everything one
hand-written invocation produces (nested and sibling expansions together), 16,384
iterations of one repetition, and a step budget of 250,000 for the matcher. Two
further ceilings cap the work of many invocations together, each reported once:
500,000 per source file, enforced while the file is analysed, and 2,000,000 per
analysis (tokens produced plus a tenth of the matcher steps), so copies of one
hostile macro cannot add up. The per-file pass measures each file's expansion work
under an unbounded ledger, file by file in path order, and stops measuring at the
first file whose running total crosses the analysis ceiling; a repair pass then
re-analyses that file with whatever work is left before the line and the files
after it in path order without expansion. Which invocations keep their expansions
is therefore a function of the input alone, not of the order the workers charge
the ledger in. A run whose measurements stay under the ceiling keeps every
expansion, so real code pays nothing for this; the worst case is the analysis
ceiling plus one measured round of overshoot (one file ceiling per worker), plus
the repair pass parsing and walking the files past the cut without expanding them.
Source that nests groups more than 64 deep is not read. No input is meant to make
the module panic: it avoids `unwrap`, `expect`, direct identifier construction and
unchecked indexing on data that comes from the source.

Where it differs from rustc, rusi accepts more and never invents flows:

- Fragments are parsed with `syn`, so the accepted grammar can differ at the edges, and a
  fragment that does not parse makes the rule not match where rustc stops with an error.
  `pat` follows the edition of the defining crate; `expr_2021` reads as `expr`.
- Matchers rustc would reject when the macro is defined (follow-set and ambiguity rules)
  are not checked up front. An ambiguity is reported when an invocation reaches it.
  `$(x),?` is accepted.
- Only `expr` bindings are kept grouped; `ty`, `pat`, `path` and the other fragments are
  spliced as plain tokens.
- Hygiene is recognized from tokens, so it relies on the conventions rustc lints for:
  bindings are `snake_case`, and constructors and types start with a capital letter. It
  does not follow block scopes (a name renamed once is renamed in the whole template),
  does not rename inside nested `fn` items, attributes or `use` items, and does not model
  labels and lifetimes.
- A macro defined by a transcriber is not declared or put in scope, so an invocation of
  it (`inner_def!` producing `made!`, then `made!()`) is not expanded. A `use` inside a
  block does not import macros. A glob import from a dependency (`use log::*;`) leaves a
  bare macro name unresolved. Dependency macros, procedural macros and `macro` 2.0 items
  are not expanded.
- Source nested thousands of groups deep can overflow the stack inside `syn` before the
  expander sees it, on any input rusi reads.

The compiler backend reads the crate after rustc's own expansion, so it does not use
this module; what it reports about macros is described in section 4.7.

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
projections, and call terminators with their resolved targets and arguments. A call
terminator takes the resolution HIR gave the same call, found by the span of the whole call
and the function it calls; the function is part of the key because desugaring can put
several calls at one span, as a `for` loop does with `into_iter` and `next`. When the
calling body's own types settle which impl a trait method call reaches, as `Self::m(..)`
does inside an impl, the call targets that impl method, the way the monomorphization pass
settles it for each instantiation of a generic body. Only calls HIR never sees, such as the
`Deref::deref` of an auto-deref, fall back to finding a local function by name. Working from
MIR rather than from source means the analysis sees the program after desugaring, so
patterns that are implicit in source, such as the operations behind operators and the
control flow behind combinators, are explicit.

### 4.3 A real MIR dataflow analysis

The compiler backend does not merely collect call edges. It runs two genuine fixpoint
dataflow passes over the reconstructed control flow graph. The abstract pass computes,
per basic block, a lattice of place to origin taint with set union as the join, and it
iterates to a fixpoint. The concrete pass materializes witness paths in the same way the
stable backend does, but over MIR places rather than syntactic variables, which gives it
access path precision keyed on locals and their projections rather than on names. Both
passes visit blocks with the min-rank worklist described in section 5, so a block is only
revisited when its entry state grew and a loop settles before the code after it runs.
Neither pass reports anything while it iterates. Once the entry states settle, the
abstract pass reads its summary off them in one pass over the blocks, and the concrete
pass transfers each reachable block once more from its settled entry state to record
slices, graph nodes and diagnostics, so each call is reported once and from the fixpoint.
Interprocedural behavior is again summary based, computed callees first over the call
graph, with summaries that capture parameter to return, parameter to sink, source to
sink, field return, and field write effects. These effect shapes are surfaced in the
report so that a reviewer can see not only that a function is relevant but in what way it
moves data.

What a call contributes that does not depend on the state it is reached in, its source
and sink models, its effect shape, and the local functions it may reach, is worked out
once per call when the crate's bodies are indexed, not on every visit. An ambiguous trait
or unresolved call reaches every trait impl method its name can denote; the candidates
come from an index keyed on the trait and method rather than a scan of every function,
and they are never truncated. Inherent methods are never candidates: Rust resolves a call
to an inherent method statically, so the call already names it as its target, and no
trait object or trait bound can dispatch to one.

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

Two calls the monomorphization pass cannot pin are resolved by enumeration instead. A
`cargo check` run emits metadata only, so the crate generates no mono items and the
collector behind the devirtualization pass sees none; a call inside a generic impl whose
trait arguments are still the impl's own parameters
(`<Uuid as ToJson<Ctx>>::to_json` inside `impl<Ctx> ToJson<Ctx> for Product`) resolves
exactly nowhere, and a call into a dependency's generic function
(`Client::<ApiCtx>::enc::<Uuid>`, whose body may not even be collected) names the
dependency's function alone. Both are answered from the trait's local implementations: the
generic call takes the bounded set of local impls of the trait whose self type and
arguments may match the ones it wrote, where a generic parameter on either side, a
lifetime, or a type the matcher does not take apart (a projection, a trait object, a
closure) never rules an impl out; the dependency call reads the trait bounds on the callee's signature
with the arguments the call site wrote (`T: ToJson<X>` becomes `Uuid: ToJson<ApiCtx>`) and
adds an edge to the matching local impl, marked `trait-callback`. The callback's fan-out
is capped the way `--max-call-candidates` caps an over-approximated call site. That edge
is what connects a user's own impls to reachability when ORMs, serializers and codecs call
them through bounds.

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
crossing into foreign code can still be reasoned about at the boundary. A function declared
in an `extern` block is named by its Rust path like any other item (`pkg::puts`), while
the models name C functions by the symbol they link against (`puts`, or whatever
`#[link_name]` gives). The compiler backend therefore matches them only against the linked
symbol of a call it knows to be foreign, so a Rust function that happens to be called `open`
is never taken for the C one. The foreign code
itself is not analyzed, so taint through a C body is modeled rather than proven, and this
is stated in the evidence confidence. Deeper cross language tracking, including parsing of
generated bindings and of native build inputs, is identified as future work rather than
claimed as present.

### 4.7 Macro expansions

The compiler backend sees the crate after rustc has expanded every macro, so code a
macro generated is code it can analyze. rustc records, for every span an expansion
produced, which expansion made it, which macro defines that expansion, and where the
invocation sits. The wrapper reads that record for every span it resolves evidence
from, and it decides three things from it.

A workspace macro is one defined by the analyzed crate or by another crate under the
analysis root. Macros of std, core, alloc, and of registry and path dependencies
outside the root, are not workspace macros.

First, signals. A security signal whose span was produced by macro expansions, and
none of which is a workspace macro, belongs to the dependency that wrote the code,
not to the analyzed code, and is not emitted. This is what removes the
"compiler-generated unsafe block" that a `log::info!` invocation used to raise
against the user's line. A signal inside a workspace macro's expansion is kept,
because the workspace's own macro caused the code to exist.
Tokens the user passes to a macro keep their own spans, so an `unsafe` block
written as an argument to `info!` or `vec!` is still reported. The rule covers
attribute and derive macros too: when a dependency's attribute macro rewrites a
workspace function, such as `#[tracing::instrument]` on an `async fn`, the
coroutine it builds is the macro's code, and the "async coroutine modeled" note
for that function is not emitted, while the user's statements inside it keep
their signals.

Second, origin. Evidence a workspace macro generated carries `expanded_from`, the
same field the stable backend fills: the outermost workspace macro of the span's
backtrace names the origin for declarations, usages, signals, call-graph edges, and
data-flow nodes, so a method `make_units!` generated and the flows inside it point
at the macro. The location is the transcriber token the macro wrote the code from,
or the definition when the token was pasted from the invocation arguments.
Positions and evidence ids stay at the call site.

Third, attribution of a dependency macro's calls. A usage or edge inside a
dependency bang macro's expansion carries a `viaMacro` property naming the macro
the invoking line wrote (`log::info!`), taken from the outermost dependency macro
of the backtrace; expansions the dependency makes inside it, such as log's
`__log!`, are its own plumbing and are not named. The callee name stays the helper
the expansion actually calls, `log::__private_api::log`. std, core and alloc
macros are not named as dependency calls, matching the stable backend's
resolution, and their signals are still dropped by the first rule. Each such
invocation is also recorded as the `macro-call` usage and the `macro` call-graph
edge the stable backend records, once per call site, so both backends report the
same macro-level calls; on the macro-zoo-app fixture the two sets agree exactly.
Where they merge, the compiler's entry replaces the stable one at the same call
site, and a signal both backends raise at one position is reported once from the
compiler's. Two differences remain and are deliberate. A stable `macro-call` whose
name the stable backend could not resolve carries its candidate list under
`properties.candidates` and no purl, while the compiler names the macro from the
expansion data, so the two entries carry different names and both are kept. And
the compiler reports calls the stable backend cannot see at all: macros invoked
inside the body of a dependency macro the stable backend leaves unanalyzed, such
as a `tracing::span!` inside a `tokio::select!` arm, and macros a procedural
macro's expansion makes, such as the `clap::value_parser!` calls a
`#[derive(Parser)]` generates. Both sets are macro-level calls the report is
better for having, so the compiler's entries are kept rather than reconciled
away.

Finally, diagnostics. In compiler mode the stable analysis still runs, and a file
whose macro bodies it could not recover contributed its "bodies were not analyzed"
note to the merged report even where the compiler had expanded those bodies. Notes
about macro bodies are left out for the files the compiler payload covers, and
kept for the files it did not reach, for example a crate whose compilation failed.

## 5. How the fixpoints converge

Both backends reach fixpoints at two levels, over a function's control flow and over the
call graph, and neither level bounds how many rounds it runs. Earlier versions did: the
stable summary pass stopped after six rounds, the compiler backend after eight, the
compiler backend's block passes after 64, and stable loops were not iterated at all. Each
of those limits silently dropped real flows, a call chain seven functions deep in the
stable backend, nine in the compiler backend, or a value carried 63 times around a loop.
The fixture `fixtures/fixpoint-flow-app` holds one of each.

The worklists live in `rusi_schema::fixpoint` and are shared by both backends.

*Min-rank traversal.* Every item has a rank in dataflow order and the worklist always
yields the lowest-ranked dirty item. When a back edge dirties an earlier item the
traversal returns to it at once rather than first running later items on input that is
about to change. rustc adopted the same algorithm for its MIR dataflow analyses in
rust-lang/rust#160193. Loop-free input is finished in one pass, one evaluation per item.

*Weak topological order.* rustc ranks blocks in reverse postorder. Reverse postorder alone
can rank a loop's exit, and all the code after it, ahead of the loop body, depending only
on the order a block lists its successors in, and min-rank then walks the rest of the
function again on every trip around the loop. Rusi ranks blocks by a weak topological
order (Bourdoncle, 1993): the strongly connected components in topological order, each
loop's head first and its body right after it, nested loops inside. Every loop is one
contiguous run of ranks, so min-rank settles loops innermost first and reaches a loop's
exit once the loop is stable, whatever the successor order.

*Callee-first call graphs.* Functions are ranked by the condensation of their call graph,
leaves first, with each recursion cycle kept together. The compiler backend runs min-rank
over that order; the stable backend runs it a whole level at a time, evaluating the level
in parallel, because nothing on one level calls anything else on it outside a recursion
cycle. Each evaluation records the summaries it read, and a grown summary re-dirties
exactly those readers, so correctness does not depend on the static call graph being
complete.

*Loops in the stable backend.* The stable backend has no control flow graph, only a
function's operations in source order with loop regions over them, so it iterates each
region directly. A loop keeps the head it settled on between entries: when the loop around
it walks its body again, the inner loop resumes from that head joined with the new entry,
and if the entry adds nothing it is not walked at all. The enclosing loop's head only
grows, so the inner loop's entry does too, and resuming reaches the fixpoint that starting
over would, without repeating the climb. Each walk of a loop grows its head, finds it
settled, or emits; a settling walk happens once for the first entry and once for each later
entry that grew the head. A loop whose head can hold F name and origin pairs is therefore
walked at most F + 2 times however deeply it is nested, and nested loops cost the sum of
their fixpoints rather than the product. Restarting inner loops on every trip of their
parent instead walks the innermost body of a nest 16 deep 3 * 2^15 times; resuming walks
it four times.

*Emitting from the fixpoint.* In both backends the passes that build slices emit nothing
while they iterate. They bring every state to its fixpoint and then make one last pass
over it, the stable backend walking each settled loop body once more and the compiler
backend transferring each reachable block once from its settled entry state, and only that
pass records slices, graph nodes and edges, and diagnostics. Every operation is reported
once, in the state the fixpoint holds there: a witness does not depend on which trip first
reached a sink, and the count of calls where taint may be lost counts each call site once,
including one that taint reaches only after going around a loop.

*Termination.* An item is marked dirty only when a join strictly added to a state, and
every state is drawn from a finite set: parameter indexes, pattern categories, names and
places taken from the program. One place set is not finite by itself. A function that
recurses on a field of its own parameter (`walk(&node.next)`) would add `node.next.val`,
then `node.next.next.val`, and so on, if a summary place were rebased onto the argument
and extended with the callee's projections on every trip around the cycle. Inside a
recursion cycle the compiler backend therefore rebases such a place onto the argument
alone. The argument covers everything under it, so this only coarsens, and it is the one
widening either backend applies. Alias chains are followed until an alias entry would be
used twice, which bounds the chase by the number of entries rather than a hop count.

*Witnesses, and what is still bounded.* A value keeps, for every origin that reaches it,
the first witness found for that origin, whole, however long it is; the seventy-step
witness in the fixture has 71 edges. Joins never trade a witness they hold for another,
and they report growth only when a name (in the stable backend) or a place (in the
compiler backend) gains an origin it did not carry, or an alias gains a place it did not
have. The concrete passes therefore end on the same finite pairs as the abstract ones. In
the compiler backend an alias keeps the first place it was given, and the places are the
body's own MIR places and summary places rebased onto its arguments, resolved through
those aliases, with the summaries already fixed when a body is materialized. The compiler backend reads one witness per origin at a place. The stable backend
may also keep other witnesses of an origin that already has one, while the value holds
fewer than 32 witnesses and only up to 64 steps long; that limit bounds memory and no
origin is ever dropped for it. The stable backend's type bindings are re-derived pass by pass until a pass
changes nothing, for at most one pass more than the function has assignments, which is
as many as a chain of dependent assignments can need; the bound only stops reassignments
that feed types around a cycle with no fixpoint. The call graph edges emitted for one
ambiguous call site are capped by `--max-call-candidates`, a report size control that
marks the site and reports the truncation; data flow does not use that cap.

*Stack depth.* Parsing and lowering are recursive, so the stack decides how deeply nested
an expression rusi can take. Analysis runs on threads with 16 MiB of stack, the size
rustc runs its compiler on since rust-lang/rust#160535, so source that rustc accepts does
not overflow rusi. `RUST_MIN_STACK` overrides it. `fixtures/deep-nesting-app` holds an
expression 800 levels deep.

## 6. Cryptography evidence

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

## 7. What is novel here

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

## 8. Scope and honest limitations

The stable backend is syntax and type hint driven. It expands workspace `macro_rules!`
invocations itself, so code those macros generate is visible; it does not expand
dependency macros, procedural macros, or `macro` 2.0 items, and it cannot resolve calls
through function pointers held in data. It is a fast approximation and it is labeled as
such.

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

## 9. Design note: context-sensitive summaries for receiver-typed sinks

The stable backend computes one summary per function, however its callers call it. That
context insensitivity is usually the right trade: a summary that unifies over call sites
is what makes the interprocedural analysis scale. It costs precision in exactly one place
today, and this note describes how that one place can be recovered the way the next rust
trait solver recovers cache precision, by recording when a computation depended on
information it did not have and paying to redo only that computation, in only that
context.

### 9.1 Where the type is missing

A receiver-typed sink pattern (`receiver_type: "Command"` on `arg`) fires only when the
call's receiver type was resolved to the pattern's type. Two places make that decision
against a summary's definition rather than a caller's site:

1. In `summarize_function`, the `Operation::Expr` / `Operation::Return` arm computes
   `receiver_type` with `infer_expr_type` over the function's own type bindings
   (`infer_type_bindings` of the callee's body: constructed types, field types, return
   types). A wrapper whose parameter carries the sink's receiver
   (`fn forward<T: Bound>(target: &mut T, v: &str) { target.arg(v) }`) binds `target` to
   nothing the stable backend can name, so `receiver_type` is `None`, and
   `receiver_type_matches` refuses a pattern with a `receiver_type` restriction: the
   sink never fires, and the wrapper's summary records no `param_to_sink` entry. The
   caller that passes a `Command` loses the flow. The same computation happens in the
   concrete pass's `materialize_operation`, which consults the callee's summary rather
   than re-deriving the match, so the slice disappears with the summary entry.
2. The auto-discovered passthrough mechanism is gated on evidence that a method forwards
   a parameter to its result, which is independent of this problem, and a method that
   matches a sanitizer is never a passthrough. The gap above is specifically
   receiver-typed *sink* matching where the receiver's type is a parameter of the
   function being summarized.

### 9.2 What the flag records

`FunctionSummary` gains one field, `receiver_type_pending: bool`. While summarizing, when
a sink candidate matches the callee text by name and its `receiver_type` restriction is
the only reason it does not fire (`receiver_type_matches` false because the resolved
receiver type was `None`), the flag is set and nothing else happens: no sink entry is
recorded, so a summary whose callers all pass unresolvable receivers behaves exactly as
today. The flag records the fact this summary would differ in some context, not which
type was missing; the set of types that could matter is the caller's knowledge, which
the summary cannot enumerate.

The flag joins like the rest of the summary: once any evaluation sets it, it stays set.
A summary that carries it is still a sound over-approximation of the function's own
behavior; it is simply marked as one whose precision a knowing caller can raise.

### 9.3 The call-site application and its memo key

When a caller's evaluation resolves a call to a callee whose summary carries the flag,
and the caller's type bindings resolve the call's receiver argument to a concrete type
(`infer_expr_type` at the call site, where the constructed type of the receiver binding
is visible), the caller re-summarizes the callee in that context: it runs the ordinary
`summarize_function` on the callee's record with the callee's own inferred type bindings
plus one binding added, the callee's receiver parameter (its parameter 0) named as the
concrete type. The receiver-typed sink then fires inside that contextual evaluation, and
the caller reads the resulting summary the way it reads the context-free one, applying
`param_to_sink` to its arguments.

The memo key is the callee's function position plus exactly the type that was missing,
`(callee position, receiver type)`, not the caller, not the call site, and not the rest
of the caller's bindings, because those cannot affect what the contextual evaluation sees:
the evaluation runs on the callee's body with one binding added. The memo lives for one
caller evaluation; a shared memo would be written by the parallel wave and would need
synchronization for no measured gain, since a caller evaluation needs at most a handful
of contextual summaries. When the caller cannot resolve the receiver type, the
context-free summary is used as is, which is today's behavior.

The same application runs in the concrete pass (`materialize_operation`), through a
positional view of the keyed summary map, so the slice exists and not only the caller's
summary claim. Both passes resolve through `CallTables`, so both see the same contexts
and the two cannot disagree about whether a flow was reported.

### 9.4 Interaction with the fixpoint and termination

The contextual evaluation is an ordinary `summarize_function` run inside the caller's
evaluation, on the callee's body, with the fixpoint's current summary table as its callee
summaries. Because it runs with the caller's `TrackedIndexReads` in its hand, every
summary it reads is recorded as a read of the caller's evaluation: when one of those
grows, the wave worklist re-dirties the caller, the caller re-evaluates, and the
contextual summary is recomputed against the grown table. The callee's own summary is
also read (for the flag and for the call's other effects), so a grown callee re-dirties
the caller the same way. Nothing about `Dependents` changes.

Termination holds for three reasons. First, the contextual evaluation runs with the
contextual path itself disabled: a summary computed in a context does not set the
pending flag's recovery in motion again: contexts do not nest, so the re-summary graph
is one level deep. Second, the contextual evaluation's states draw from the same finite
domains as any evaluation (names, origins, places taken from the callee's body), and its
result joins into the caller's summary, which joins monotonically and only over finite
sets; no new iteration mechanism is added to the fixpoint, only a deterministic function
of the current table. Third, the memo bounds the work within one evaluation: each
(callee, type) pair is summarized at most once per evaluation, and the pairs are finite
because the types come from the caller's finite binding set.

### 9.5 What is deliberately not covered

Trait dispatch, generic bounds beyond the receiver parameter, and associated types stay
out: the flag records one missing piece of information, the receiver parameter's type,
and the recovery supplies exactly that. A summary whose precision depends on something
wider (a whole trait implementation choice, for instance) needs the same machinery with
a different flag and key, and this note's shape extends to it; the receiver-typed sink
case is the one measured gap in the stable backend's flow coverage, so it is the one
implemented.

## 10. Design note: a summary cache shared across crates

The dependency mode today analyzes every dependency crate's functions each run. The
stable backend's dependency tier already collects bodies only under
`security-deps`, and a dependency closure is typically an order of magnitude larger
than the workspace, so summarizing a dependency whose source has not changed is the
same work every run. A per-dependency summary cache follows the trait solver's cache
key lesson: the key must contain everything that can change a summary and nothing else.

### 10.1 The key

An entry is keyed on:

- the dependency's package name and exact version, as resolved by `cargo metadata`;
- a checksum of the crate's source: the `Cargo.lock` checksum for a registry
  dependency, and for a path or git dependency the hash over the collected source
  files' contents, since neither source of truth has a registry checksum that covers
  what was read;
- the feature set Cargo resolved for that crate, in sorted order (features can gate
  code, and gated code changes summaries);
- the active cfg set fingerprint (target triple and the options `cfg` evaluation
  used), for the same reason;
- the rusi version and the summary schema version, so an upgrade invalidates every
  entry rather than misreading old ones;
- a hash of only the source and sink patterns that matched at least one callee in
  that crate during the run that produced the entry. This is the piece that keeps an
  unrelated pattern edit from invalidating every cache entry: a new `Command::arg`
  rule invalidates only the crates whose bodies mention a matched callee, not the
  crates whose summaries could not have consulted it. The cost is that the cache
  records, per crate, the set of matching patterns; that set is small (pattern
  categories and texts, not call sites). Passthrough patterns are part of this hash
  too, because an auto-discovered passthrough changes what flows through a body.

Everything else that a summary depends on is a function of the source plus the callee
summaries, and callee summaries are reached transitively: a dependency's summaries are
stored together as one entry, so a call into another dependency either resolves inside
the same entry or marks the entry as depending on a second crate's (name, version,
checksum), which is checked before the entry is reused. Two dependencies whose sources
call into each other share one entry keyed on both.

### 10.2 Where entries live

Under `rusi_cache_base`, the per-user directory the embedded wrapper build already
uses, which enforces an absolute path, has no fallback to the system temp directory,
and ignores relative `XDG_CACHE_HOME` and `HOME` values. The layout is
`<cache>/summaries/<key-hash>.json`, one file per dependency, written atomically. The
key hash is the SHA-256 of the canonical key fields, length-prefixed in a fixed order,
the way the fetch cache derives its entry names, so a reader that disagrees about the
key simply misses rather than misreads.

### 10.3 How summaries name functions across runs

Inside the fixpoint, summaries are rows addressed by position; the keyed map they
become is keyed on the declaration id, which is stable only within a run. Entries
therefore store summaries keyed by `canonical_name()`, the schema's generic-free,
lifetime-free, hash-free function path, which is already the join key between a
source-level and a binary-level call graph. On a cache hit the entry's names are
resolved back into the run's tables: a name that no longer resolves (the dependency's
own source changed, so the checksum would have differed) cannot occur inside one
entry; a cross-dependency reference resolves against the referenced crate's entry, or
the whole entry is discarded if that crate's key changed.

### 10.4 Size bounds and eviction

The cache has a byte ceiling with the same shape as the fetch cache's: a default
ceiling, an enforcement pass that walks the directory and evicts by access time
(moved forward on a hit without writing bytes), and a slack budget between passes so
a typical scan does not pay for the walk. An entry is bounded by what its crate
produces; a hostile crate cannot inflate an entry beyond what summarizing it would
have produced in memory anyway, and the entry write is capped at that size. A sweep
also drops entries whose schema version or key generation is not the current one, so
an upgrade reclaims rather than accumulates.

### 10.5 Threats, from THREAT_MODEL.md

A cache another process could write is an untrusted input. The threats that apply:

1. A planted entry could fabricate findings, or worse, suppress them: a hostile
   `param_to_sink` that never fires turns a real flow silent. Every entry therefore
   carries the key fields it was built from, and the reader recomputes the key hash
   from what it holds against the directory name before trusting the contents; an
   entry moved from another key is rejected. The summary schema version and rusi
   version inside the entry must match the running tool.
2. A hostile entry could carry malformed JSON, absurd sizes, or hostile paths. The
   entry's JSON is parsed with the same schema types the wrapper's artifacts use, so
   a malformed entry is a rejected entry, not a panic; the parse is size-capped by
   the byte ceiling's per-entry bound. An entry stores no paths: functions are named
   by `canonical_name()`, sources and sinks by category, and nothing in an entry is
   ever turned into a filesystem path or executed.
3. A hostile entry could reference a second crate's entry that was replaced after
   the fact. Cross-dependency references store the referenced crate's key fields, and
   the reference is re-checked against the current directory contents on every read;
   a mismatch discards the referencing entry.
4. The directory itself is per-user (no world-writable fallback), so another local
   user cannot plant entries unless they can already write the user's cache; the
   fetch cache documents the same boundary. Entries are validated on read regardless,
   on the assumption the directory may be hostile anyway.

What a corrupted or hostile entry costs under these rules is a cache miss and a
re-summary, never a wrong answer: rejection is the only recovery the reader has, and
it is always available because every entry can be recomputed from source.
