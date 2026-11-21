//! The `macro_rules!` matcher.
//!
//! Matching follows rustc's design: the matcher is compiled to a flat list of
//! locations, every live position (a "thread") advances over the input one
//! token at a time, and a fragment specifier is parsed only when exactly one
//! thread waits for it. Two threads waiting for a fragment, or a thread
//! waiting for a fragment next to one waiting for a literal token, is the
//! local ambiguity rustc rejects with a compile error, so a crate that
//! compiles never reaches it and rusi reports it instead of guessing.
//!
//! Because the threads run in lockstep and are de-duplicated by position, the
//! work is bounded by the matcher size times the input length. A separate
//! step budget still caps one expansion, so a matcher and input rustc would
//! reject cannot keep the analysis running.

use std::collections::{HashMap, HashSet};

use proc_macro2::{Delimiter, Group, Spacing, TokenStream, TokenTree};
use syn::Token;
use syn::parse::{ParseStream, Parser};

use super::{MAX_NESTING, MAX_REPETITION_ITERATIONS};

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

/// A fragment specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Frag {
    Item,
    Block,
    Stmt,
    /// A pattern that accepts a top-level or-pattern (edition 2021 and later).
    Pat,
    /// A pattern without a top-level or-pattern (`pat_param`, and `pat`
    /// before edition 2021).
    PatParam,
    Expr,
    Ty,
    Ident,
    Path,
    Tt,
    Meta,
    Lifetime,
    Vis,
    Literal,
}

impl Frag {
    fn from_name(name: &str, edition_2021: bool) -> Option<Self> {
        Some(match name {
            "item" => Self::Item,
            "block" => Self::Block,
            "stmt" => Self::Stmt,
            "pat" if edition_2021 => Self::Pat,
            "pat" | "pat_param" => Self::PatParam,
            "expr" | "expr_2021" => Self::Expr,
            "ty" => Self::Ty,
            "ident" => Self::Ident,
            "path" => Self::Path,
            "tt" => Self::Tt,
            "meta" => Self::Meta,
            "lifetime" => Self::Lifetime,
            "vis" => Self::Vis,
            "literal" => Self::Literal,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Op {
    ZeroOrMore,
    OneOrMore,
    ZeroOrOne,
}

impl Op {
    pub(super) fn from_char(c: char) -> Option<Self> {
        match c {
            '*' => Some(Self::ZeroOrMore),
            '+' => Some(Self::OneOrMore),
            '?' => Some(Self::ZeroOrOne),
            _ => None,
        }
    }
}

/// One element of a parsed matcher.
#[derive(Debug, Clone)]
pub(super) enum MPat {
    /// A literal token, compared by its text.
    Tok(String),
    Delim(Delimiter, Vec<MPat>),
    Var {
        name: String,
        frag: Frag,
    },
    Rep {
        body: Vec<MPat>,
        sep: Option<String>,
        op: Op,
    },
}

const OPS3: &[&str] = &["<<=", ">>=", "...", "..="];
const OPS2: &[&str] = &[
    "::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "^=", "&=",
    "|=", "<<", ">>", "..",
];

/// The token starting at `trees[i]` as rustc reads it: a run of joint
/// punctuation that forms one operator, a lifetime, or one tree. Returns the
/// number of trees it spans and its text. `trees[i]` must not be a group.
pub(super) fn token_at(trees: &[TokenTree], i: usize) -> Option<(usize, String)> {
    match trees.get(i)? {
        TokenTree::Group(_) => None,
        TokenTree::Ident(ident) => Some((1, ident.to_string())),
        TokenTree::Literal(literal) => Some((1, literal.to_string())),
        TokenTree::Punct(first) => {
            if first.as_char() == '\''
                && let Some(TokenTree::Ident(ident)) = trees.get(i + 1)
            {
                return Some((2, format!("'{ident}")));
            }
            let mut text = String::new();
            text.push(first.as_char());
            let mut span = 1usize;
            let mut prev_joint = first.spacing() == Spacing::Joint;
            let mut best = (1usize, text.clone());
            while prev_joint && span < 3 {
                let Some(TokenTree::Punct(next)) = trees.get(i + span) else {
                    break;
                };
                text.push(next.as_char());
                span += 1;
                let table = if span == 3 { OPS3 } else { OPS2 };
                if table.contains(&text.as_str()) {
                    best = (span, text.clone());
                }
                prev_joint = next.spacing() == Spacing::Joint;
            }
            Some(best)
        }
    }
}

/// Parses a matcher. Fails when the pattern is malformed or nests deeper than
/// the module's bound.
pub(super) fn parse_matcher(stream: TokenStream, edition_2021: bool) -> Result<Vec<MPat>, String> {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    parse_seq(&trees, edition_2021, 0)
}

fn parse_seq(trees: &[TokenTree], edition_2021: bool, depth: usize) -> Result<Vec<MPat>, String> {
    if depth > MAX_NESTING {
        return Err("matcher nesting is too deep".to_string());
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < trees.len() {
        match &trees[i] {
            TokenTree::Group(group) => {
                let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                out.push(MPat::Delim(
                    group.delimiter(),
                    parse_seq(&inner, edition_2021, depth + 1)?,
                ));
                i += 1;
            }
            TokenTree::Punct(punct) if punct.as_char() == '$' => match trees.get(i + 1) {
                Some(TokenTree::Ident(name)) if name == "crate" => {
                    out.push(MPat::Tok("$crate".to_string()));
                    i += 2;
                }
                Some(TokenTree::Ident(name)) => {
                    let spec = match (trees.get(i + 2), trees.get(i + 3)) {
                        (Some(TokenTree::Punct(colon)), Some(TokenTree::Ident(spec)))
                            if colon.as_char() == ':' =>
                        {
                            spec.to_string()
                        }
                        _ => return Err(format!("`${name}` has no fragment specifier")),
                    };
                    let frag = Frag::from_name(&spec, edition_2021)
                        .ok_or_else(|| format!("unknown fragment specifier `{spec}`"))?;
                    out.push(MPat::Var {
                        name: name.to_string(),
                        frag,
                    });
                    i += 4;
                }
                Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis => {
                    let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                    let body = parse_seq(&inner, edition_2021, depth + 1)?;
                    let (sep, op, used) = read_repetition_tail(trees, i + 2)?;
                    out.push(MPat::Rep { body, sep, op });
                    i += 2 + used;
                }
                _ => {
                    out.push(MPat::Tok("$".to_string()));
                    i += 1;
                }
            },
            _ => {
                let (span, text) =
                    token_at(trees, i).ok_or_else(|| "unexpected group".to_string())?;
                out.push(MPat::Tok(text));
                i += span;
            }
        }
    }
    Ok(out)
}

/// Reads the separator and operator after a `$( ... )` group starting at
/// `trees[at]`. The separator is one token in rustc's sense, so a joint run
/// such as `::` or `=>` is a single separator. Returns the separator, the
/// operator and the number of trees consumed.
pub(super) fn read_repetition_tail(
    trees: &[TokenTree],
    at: usize,
) -> Result<(Option<String>, Op, usize), String> {
    let missing = || "a repetition has no `*`, `+` or `?` operator".to_string();
    let first = trees.get(at).ok_or_else(missing)?;
    if let TokenTree::Punct(punct) = first
        && let Some(op) = Op::from_char(punct.as_char())
    {
        // `$(..)+=` style input reads the joint run as one separator below,
        // so a bare operator is only one when it is not joint with another
        // punctuation character that continues a known operator.
        let joint_continues = punct.spacing() == Spacing::Joint
            && token_at(trees, at).is_some_and(|(span, _)| span > 1);
        if !joint_continues {
            return Ok((None, op, 1));
        }
    }
    let (span, text) = token_at(trees, at).ok_or_else(missing)?;
    match trees.get(at + span) {
        Some(TokenTree::Punct(punct)) if Op::from_char(punct.as_char()).is_some() => {
            let op = Op::from_char(punct.as_char()).ok_or_else(missing)?;
            Ok((Some(text), op, span + 1))
        }
        _ => Err(missing()),
    }
}

// ---------------------------------------------------------------------------
// Compilation to locations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Loc {
    Tok(String),
    Open(Delimiter),
    Close(Delimiter),
    Var {
        var: usize,
        frag: Frag,
    },
    /// Epsilon: enter the body, or skip to `after` when zero iterations are
    /// allowed.
    SeqStart {
        after: usize,
        can_skip: bool,
        rep: usize,
    },
    /// Epsilon: leave the repetition at `after`, or start another iteration
    /// at the next location.
    SeqEnd {
        after: usize,
        can_loop: bool,
    },
    Jump(usize),
    Eof,
}

/// A compiled matcher.
#[derive(Debug)]
pub(super) struct Compiled {
    locs: Vec<Loc>,
    /// Metavariable names, indexed by the `var` of a location.
    vars: Vec<String>,
    frags: Vec<Frag>,
    /// For each repetition, every metavariable inside it, nested ones
    /// included.
    rep_vars: Vec<Vec<usize>>,
}

pub(super) fn compile(pattern: &[MPat]) -> Compiled {
    let mut compiled = Compiled {
        locs: Vec::new(),
        vars: Vec::new(),
        frags: Vec::new(),
        rep_vars: Vec::new(),
    };
    let mut names: HashMap<String, usize> = HashMap::new();
    let mut rep_stack = Vec::new();
    compile_seq(pattern, &mut compiled, &mut names, &mut rep_stack);
    compiled.locs.push(Loc::Eof);
    compiled
}

fn compile_seq(
    pattern: &[MPat],
    out: &mut Compiled,
    names: &mut HashMap<String, usize>,
    rep_stack: &mut Vec<usize>,
) {
    for element in pattern {
        match element {
            MPat::Tok(text) => out.locs.push(Loc::Tok(text.clone())),
            MPat::Delim(delimiter, inner) => {
                out.locs.push(Loc::Open(*delimiter));
                compile_seq(inner, out, names, rep_stack);
                out.locs.push(Loc::Close(*delimiter));
            }
            MPat::Var { name, frag } => {
                let var = *names.entry(name.clone()).or_insert_with(|| {
                    out.vars.push(name.clone());
                    out.frags.push(*frag);
                    out.vars.len() - 1
                });
                for rep in rep_stack.iter() {
                    if !out.rep_vars[*rep].contains(&var) {
                        out.rep_vars[*rep].push(var);
                    }
                }
                out.locs.push(Loc::Var { var, frag: *frag });
            }
            MPat::Rep { body, sep, op } => {
                let rep = out.rep_vars.len();
                out.rep_vars.push(Vec::new());
                let start = out.locs.len();
                out.locs.push(Loc::SeqStart {
                    after: 0,
                    can_skip: *op != Op::OneOrMore,
                    rep,
                });
                rep_stack.push(rep);
                compile_seq(body, out, names, rep_stack);
                rep_stack.pop();
                let end = out.locs.len();
                let can_loop = *op != Op::ZeroOrOne;
                out.locs.push(Loc::SeqEnd { after: 0, can_loop });
                if can_loop {
                    if let Some(separator) = sep {
                        out.locs.push(Loc::Tok(separator.clone()));
                    }
                    out.locs.push(Loc::Jump(start + 1));
                }
                let after = out.locs.len();
                if let Loc::SeqStart { after: slot, .. } = &mut out.locs[start] {
                    *slot = after;
                }
                if let Loc::SeqEnd { after: slot, .. } = &mut out.locs[end] {
                    *slot = after;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// One element of the flattened input.
#[derive(Debug, Clone)]
pub(super) enum Flat {
    /// A token in rustc's sense and the trees it is made of.
    Tok {
        text: String,
        trees: Vec<TokenTree>,
    },
    Open {
        delimiter: Delimiter,
        group: Group,
        /// Index of the matching `Close`.
        close: usize,
    },
    Close(Delimiter),
}

/// The invocation tokens, flattened so that every thread shares one position.
#[derive(Debug)]
pub(super) struct FlatInput {
    toks: Vec<Flat>,
    /// For each element, the index of the `Close` that ends its level, or the
    /// input length for the top level.
    level_end: Vec<usize>,
}

impl FlatInput {
    /// Flattens `trees`. Returns `None` when the groups nest deeper than the
    /// module's bound, which no hand-written invocation does.
    pub(super) fn new(trees: &[TokenTree]) -> Option<Self> {
        let mut toks: Vec<Flat> = Vec::new();
        // Each work item is a sequence being flattened and its next index.
        let mut stack: Vec<(Vec<TokenTree>, usize, Option<usize>)> =
            vec![(trees.to_vec(), 0, None)];
        while let Some((seq, mut i, open_at)) = stack.pop() {
            let mut descend: Option<(Group, usize)> = None;
            while i < seq.len() {
                if let TokenTree::Group(group) = &seq[i] {
                    descend = Some((group.clone(), i));
                    break;
                }
                let (span, text) = token_at(&seq, i)?;
                toks.push(Flat::Tok {
                    text,
                    trees: seq[i..i + span].to_vec(),
                });
                i += span;
            }
            if let Some((group, at)) = descend {
                if stack.len() >= MAX_NESTING {
                    return None;
                }
                let here = toks.len();
                toks.push(Flat::Open {
                    delimiter: group.delimiter(),
                    group: group.clone(),
                    close: 0,
                });
                let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                stack.push((seq, at + 1, open_at));
                stack.push((inner, 0, Some(here)));
                continue;
            }
            if let Some(open) = open_at {
                let close_index = toks.len();
                let delimiter = match &toks[open] {
                    Flat::Open { delimiter, .. } => *delimiter,
                    _ => return None,
                };
                toks.push(Flat::Close(delimiter));
                if let Flat::Open { close, .. } = &mut toks[open] {
                    *close = close_index;
                }
            }
        }
        let mut level_end = vec![toks.len(); toks.len()];
        let mut pending: Vec<Vec<usize>> = vec![Vec::new()];
        for (index, element) in toks.iter().enumerate() {
            match element {
                Flat::Open { .. } => {
                    if let Some(top) = pending.last_mut() {
                        top.push(index);
                    }
                    pending.push(Vec::new());
                }
                Flat::Close(_) => {
                    if let Some(level) = pending.pop() {
                        for member in level {
                            level_end[member] = index;
                        }
                    }
                    if let Some(top) = pending.last_mut() {
                        top.push(index);
                    }
                }
                Flat::Tok { .. } => {
                    if let Some(top) = pending.last_mut() {
                        top.push(index);
                    }
                }
            }
        }
        // A fragment never starts at a `Close`, so only the other elements'
        // level ends are ever read.
        Some(Self { toks, level_end })
    }

    fn len(&self) -> usize {
        self.toks.len()
    }

    /// The trees of `toks[from..to]`, groups re-assembled.
    fn trees(&self, from: usize, to: usize) -> Vec<TokenTree> {
        let mut out = Vec::new();
        let mut i = from;
        while i < to {
            match &self.toks[i] {
                Flat::Tok { trees, .. } => {
                    out.extend(trees.iter().cloned());
                    i += 1;
                }
                Flat::Open { group, close, .. } => {
                    out.push(TokenTree::Group(group.clone()));
                    i = close + 1;
                }
                Flat::Close(_) => break,
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

/// What a metavariable matched.
#[derive(Debug, Clone)]
pub(super) enum Binding {
    Leaf { trees: Vec<TokenTree>, frag: Frag },
    Seq(Vec<Binding>),
}

pub(super) type Bindings = HashMap<String, Binding>;

#[derive(Debug, Clone, Copy)]
enum Ev {
    Bind { var: usize, from: usize, to: usize },
    Enter(usize),
    Next,
    Exit,
    Skip(usize),
}

// ---------------------------------------------------------------------------
// Budget and errors
// ---------------------------------------------------------------------------

/// Why matching stopped without a rule decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchError {
    /// rustc's local ambiguity: more than one way to continue.
    Ambiguous,
    /// The expansion's step budget was spent.
    StepBudget,
}

/// The step budget of one expansion, shared by every rule it tries.
#[derive(Debug)]
pub(super) struct Budget {
    remaining: usize,
}

impl Budget {
    pub(super) fn new(steps: usize) -> Self {
        Self { remaining: steps }
    }

    fn spend(&mut self, steps: usize) -> Result<(), MatchError> {
        if self.remaining < steps {
            self.remaining = 0;
            return Err(MatchError::StepBudget);
        }
        self.remaining -= steps;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Thread {
    pc: usize,
    /// One more than the index of this thread's last event; zero for none.
    ev: usize,
    /// Iteration counts of the repetitions this thread is inside.
    iters: Vec<u32>,
}

pub(super) enum Matched {
    Yes(Bindings),
    No {
        /// A repetition reached the iteration cap on some thread.
        iteration_cap: bool,
    },
}

/// Runs `compiled` over `input`.
pub(super) fn run(
    compiled: &Compiled,
    input: &FlatInput,
    budget: &mut Budget,
) -> Result<Matched, MatchError> {
    let mut arena: Vec<(Ev, usize)> = Vec::new();
    let mut threads = vec![Thread {
        pc: 0,
        ev: 0,
        iters: Vec::new(),
    }];
    let mut iteration_cap = false;
    let mut i = 0usize;
    loop {
        let (settled, duplicates) = close_over(
            compiled,
            input,
            i,
            threads,
            &mut arena,
            budget,
            &mut iteration_cap,
        )?;
        if i >= input.len() {
            let done = settled
                .iter()
                .find(|thread| matches!(compiled.locs[thread.pc], Loc::Eof));
            return Ok(match done {
                Some(thread) => Matched::Yes(rebuild(compiled, input, &arena, thread.ev)),
                None => Matched::No { iteration_cap },
            });
        }
        let token = &input.toks[i];
        let mut advancing: Vec<Thread> = Vec::new();
        let mut waiting: Vec<Thread> = Vec::new();
        for thread in settled {
            budget.spend(1)?;
            let accepts = match (&compiled.locs[thread.pc], token) {
                (Loc::Tok(want), Flat::Tok { text, .. }) => want == text,
                (Loc::Open(want), Flat::Open { delimiter, .. }) => want == delimiter,
                (Loc::Close(want), Flat::Close(delimiter)) => want == delimiter,
                (Loc::Var { frag, .. }, _) => {
                    if can_begin(*frag, input, i) {
                        waiting.push(thread);
                    }
                    continue;
                }
                _ => false,
            };
            if accepts {
                advancing.push(Thread {
                    pc: thread.pc + 1,
                    ..thread
                });
            }
        }
        if waiting.is_empty() && advancing.is_empty() {
            return Ok(Matched::No { iteration_cap });
        }
        // A second path to a fragment position that is already waiting is a
        // second way to match, which rustc keeps as a separate thread.
        let extra = duplicates
            .iter()
            .filter(|&&pc| match compiled.locs[pc] {
                Loc::Var { frag, .. } => can_begin(frag, input, i),
                _ => false,
            })
            .count();
        if waiting.len() + extra > 1 || (!waiting.is_empty() && !advancing.is_empty()) {
            return Err(MatchError::Ambiguous);
        }
        if let Some(thread) = waiting.pop() {
            let Loc::Var { var, frag } = compiled.locs[thread.pc] else {
                return Ok(Matched::No { iteration_cap });
            };
            let Some(end) = parse_fragment(frag, input, i, budget)? else {
                return Ok(Matched::No { iteration_cap });
            };
            arena.push((
                Ev::Bind {
                    var,
                    from: i,
                    to: end,
                },
                thread.ev,
            ));
            threads = vec![Thread {
                pc: thread.pc + 1,
                ev: arena.len(),
                iters: thread.iters,
            }];
            i = end;
        } else {
            threads = advancing;
            i += 1;
        }
    }
}

/// Follows the epsilon locations from every thread and returns the threads
/// that wait on a token, a delimiter, a fragment or the end of the input,
/// de-duplicated by position.
fn close_over(
    compiled: &Compiled,
    input: &FlatInput,
    at: usize,
    threads: Vec<Thread>,
    arena: &mut Vec<(Ev, usize)>,
    budget: &mut Budget,
    iteration_cap: &mut bool,
) -> Result<(Vec<Thread>, Vec<usize>), MatchError> {
    let mut settled: Vec<Thread> = Vec::new();
    let mut duplicates: Vec<usize> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();
    let mut stack: Vec<Thread> = threads;
    stack.reverse();
    while let Some(thread) = stack.pop() {
        budget.spend(1)?;
        if !seen.insert(thread.pc) {
            if matches!(compiled.locs[thread.pc], Loc::Var { .. }) {
                duplicates.push(thread.pc);
            }
            continue;
        }
        match &compiled.locs[thread.pc] {
            Loc::SeqStart {
                after,
                can_skip,
                rep,
            } => {
                if *can_skip {
                    arena.push((Ev::Skip(*rep), thread.ev));
                    stack.push(Thread {
                        pc: *after,
                        ev: arena.len(),
                        iters: thread.iters.clone(),
                    });
                }
                arena.push((Ev::Enter(*rep), thread.ev));
                let mut iters = thread.iters;
                iters.push(1);
                stack.push(Thread {
                    pc: thread.pc + 1,
                    ev: arena.len(),
                    iters,
                });
            }
            Loc::SeqEnd { after, can_loop } => {
                if *can_loop {
                    let count = thread.iters.last().copied().unwrap_or(0);
                    if (count as usize) < MAX_REPETITION_ITERATIONS {
                        arena.push((Ev::Next, thread.ev));
                        let mut iters = thread.iters.clone();
                        if let Some(last) = iters.last_mut() {
                            *last += 1;
                        }
                        stack.push(Thread {
                            pc: thread.pc + 1,
                            ev: arena.len(),
                            iters,
                        });
                    } else {
                        *iteration_cap = true;
                    }
                }
                arena.push((Ev::Exit, thread.ev));
                let mut iters = thread.iters;
                iters.pop();
                stack.push(Thread {
                    pc: *after,
                    ev: arena.len(),
                    iters,
                });
            }
            Loc::Jump(target) => stack.push(Thread {
                pc: *target,
                ..thread
            }),
            Loc::Var {
                var,
                frag: Frag::Vis,
            } => {
                let starts_with_pub = matches!(
                    input.toks.get(at),
                    Some(Flat::Tok { text, .. }) if text == "pub"
                );
                if starts_with_pub {
                    settled.push(thread);
                } else {
                    // A visibility is optional, so it matches nothing here.
                    arena.push((
                        Ev::Bind {
                            var: *var,
                            from: at,
                            to: at,
                        },
                        thread.ev,
                    ));
                    stack.push(Thread {
                        pc: thread.pc + 1,
                        ev: arena.len(),
                        iters: thread.iters,
                    });
                }
            }
            Loc::Tok(_) | Loc::Open(_) | Loc::Close(_) | Loc::Var { .. } | Loc::Eof => {
                settled.push(thread);
            }
        }
    }
    Ok((settled, duplicates))
}

fn rebuild(compiled: &Compiled, input: &FlatInput, arena: &[(Ev, usize)], head: usize) -> Bindings {
    let mut events = Vec::new();
    let mut at = head;
    while at != 0 {
        let (event, previous) = arena[at - 1];
        events.push(event);
        at = previous;
    }
    events.reverse();

    struct Frame {
        rep: usize,
        iterations: Vec<Bindings>,
        current: Bindings,
    }
    let mut stack = vec![Frame {
        rep: usize::MAX,
        iterations: Vec::new(),
        current: Bindings::new(),
    }];
    for event in events {
        match event {
            Ev::Bind { var, from, to } => {
                if let Some(top) = stack.last_mut() {
                    top.current.insert(
                        compiled.vars[var].clone(),
                        Binding::Leaf {
                            trees: input.trees(from, to),
                            frag: compiled.frags[var],
                        },
                    );
                }
            }
            Ev::Enter(rep) => stack.push(Frame {
                rep,
                iterations: Vec::new(),
                current: Bindings::new(),
            }),
            Ev::Next => {
                if let Some(top) = stack.last_mut() {
                    let finished = std::mem::take(&mut top.current);
                    top.iterations.push(finished);
                }
            }
            Ev::Exit => {
                if stack.len() > 1
                    && let Some(mut frame) = stack.pop()
                {
                    let last = std::mem::take(&mut frame.current);
                    frame.iterations.push(last);
                    if let Some(parent) = stack.last_mut() {
                        for &var in &compiled.rep_vars[frame.rep] {
                            let name = &compiled.vars[var];
                            let items = frame
                                .iterations
                                .iter_mut()
                                .map(|iteration| {
                                    iteration
                                        .remove(name)
                                        .unwrap_or_else(|| Binding::Seq(Vec::new()))
                                })
                                .collect();
                            parent.current.insert(name.clone(), Binding::Seq(items));
                        }
                    }
                }
            }
            Ev::Skip(rep) => {
                if let Some(top) = stack.last_mut() {
                    for &var in &compiled.rep_vars[rep] {
                        top.current
                            .insert(compiled.vars[var].clone(), Binding::Seq(Vec::new()));
                    }
                }
            }
        }
    }
    stack
        .into_iter()
        .next()
        .map(|frame| frame.current)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Fragments
// ---------------------------------------------------------------------------

fn text_at(input: &FlatInput, i: usize) -> Option<&str> {
    match input.toks.get(i)? {
        Flat::Tok { text, .. } => Some(text),
        _ => None,
    }
}

fn is_ident_token(input: &FlatInput, i: usize) -> bool {
    matches!(
        input.toks.get(i),
        Some(Flat::Tok { trees, .. })
            if trees.len() == 1 && matches!(trees[0], TokenTree::Ident(_))
    )
}

fn is_literal_token(input: &FlatInput, i: usize) -> bool {
    matches!(
        input.toks.get(i),
        Some(Flat::Tok { trees, .. })
            if trees.len() == 1 && matches!(trees[0], TokenTree::Literal(_))
    )
}

/// Whether the token at `i` can start a fragment, as rustc's check before it
/// commits a thread to parsing. It only has to rule out tokens that cannot
/// start the fragment; the parser decides the rest.
fn can_begin(frag: Frag, input: &FlatInput, i: usize) -> bool {
    let Some(element) = input.toks.get(i) else {
        return false;
    };
    if matches!(element, Flat::Close(_)) {
        return false;
    }
    let text = text_at(input, i);
    match frag {
        Frag::Tt => true,
        Frag::Ident => is_ident_token(input, i) && text != Some("_"),
        Frag::Lifetime => text.is_some_and(|text| text.starts_with('\'')),
        Frag::Literal => {
            is_literal_token(input, i)
                || matches!(text, Some("true" | "false"))
                || (text == Some("-") && is_literal_token(input, i + 1))
        }
        Frag::Block => matches!(
            element,
            Flat::Open {
                delimiter: Delimiter::Brace,
                ..
            }
        ),
        Frag::Vis => text == Some("pub"),
        Frag::Item => text.is_none_or(|text| text == "#" || is_ident_token(input, i)),
        Frag::Meta | Frag::Path => {
            is_ident_token(input, i) || matches!(text, Some("::" | "<" | "<<"))
        }
        Frag::Ty => {
            is_ident_token(input, i)
                || !matches!(element, Flat::Tok { .. })
                || text.is_some_and(|text| {
                    text.starts_with('\'')
                        || matches!(text, "!" | "*" | "&" | "&&" | "<" | "<<" | "::" | "?")
                })
        }
        Frag::Pat | Frag::PatParam => {
            !matches!(element, Flat::Tok { .. })
                || is_ident_token(input, i)
                || is_literal_token(input, i)
                || text.is_some_and(|text| {
                    matches!(
                        text,
                        "&" | "&&" | "-" | "|" | ".." | "..=" | "::" | "<" | "<<" | "_"
                    )
                })
        }
        Frag::Expr | Frag::Stmt => {
            !matches!(element, Flat::Tok { .. })
                || text.is_none_or(|text| {
                    !matches!(
                        text,
                        "," | ";"
                            | "=>"
                            | "="
                            | "?"
                            | ":"
                            | "."
                            | "+"
                            | "/"
                            | "%"
                            | "^"
                            | "=="
                            | "!="
                            | ">"
                            | "<="
                            | ">="
                            | "->"
                            | "@"
                            | "+="
                            | "-="
                            | "*="
                            | "/="
                            | "%="
                            | "^="
                            | "&="
                            | "|="
                            | "<<="
                            | ">>="
                            | ">>"
                            | "..."
                    )
                })
        }
    }
}

/// Parses the fragment starting at `input[i]` and returns the index after it,
/// or `None` when the input there is not that fragment.
fn parse_fragment(
    frag: Frag,
    input: &FlatInput,
    i: usize,
    budget: &mut Budget,
) -> Result<Option<usize>, MatchError> {
    match frag {
        Frag::Tt => Ok(match input.toks.get(i) {
            Some(Flat::Tok { .. }) => Some(i + 1),
            Some(Flat::Open { close, .. }) => Some(close + 1),
            _ => None,
        }),
        Frag::Ident | Frag::Lifetime => Ok(Some(i + 1)),
        Frag::Literal => {
            let at = if text_at(input, i) == Some("-") {
                i + 1
            } else {
                i
            };
            Ok(Some(at + 1))
        }
        Frag::Block => Ok(match input.toks.get(i) {
            Some(Flat::Open { close, .. }) => Some(close + 1),
            _ => None,
        }),
        _ => {
            let end = input.level_end.get(i).copied().unwrap_or(input.len());
            let trees = input.trees(i, end);
            budget.spend(1 + trees.len() / 64)?;
            let Some(consumed) = parse_prefix(trees, |stream| parse_by_frag(frag, stream)) else {
                return Ok(None);
            };
            Ok(advance_trees(input, i, end, consumed))
        }
    }
}

/// The flat index reached after `consumed` trees from `from`, or `None` when
/// the parser stopped inside one token.
fn advance_trees(input: &FlatInput, from: usize, end: usize, consumed: usize) -> Option<usize> {
    let mut remaining = consumed;
    let mut i = from;
    while remaining > 0 && i < end {
        match &input.toks[i] {
            Flat::Tok { trees, .. } => {
                if trees.len() > remaining {
                    return None;
                }
                remaining -= trees.len();
                i += 1;
            }
            Flat::Open { close, .. } => {
                remaining -= 1;
                i = close + 1;
            }
            Flat::Close(_) => return None,
        }
    }
    (remaining == 0).then_some(i)
}

/// Parses a prefix of `trees` with `parse` and returns how many top-level
/// trees it consumed.
fn parse_prefix<F>(trees: Vec<TokenTree>, parse: F) -> Option<usize>
where
    F: FnOnce(ParseStream) -> syn::Result<()>,
{
    let total = trees.len();
    let stream: TokenStream = trees.into_iter().collect();
    let rest_len = std::cell::Cell::new(None);
    let parser = |input: ParseStream| -> syn::Result<()> {
        parse(input)?;
        let rest: TokenStream = input.parse()?;
        rest_len.set(Some(rest.into_iter().count()));
        Ok(())
    };
    parser.parse2(stream).ok()?;
    total.checked_sub(rest_len.get()?)
}

fn parse_by_frag(frag: Frag, input: ParseStream) -> syn::Result<()> {
    match frag {
        Frag::Expr => {
            input.parse::<syn::Expr>()?;
        }
        Frag::Ty => {
            input.parse::<syn::Type>()?;
        }
        Frag::Path => {
            input.parse::<syn::Path>()?;
        }
        Frag::Pat => {
            syn::Pat::parse_multi_with_leading_vert(input)?;
        }
        Frag::PatParam => {
            syn::Pat::parse_single(input)?;
        }
        Frag::Item => {
            input.parse::<syn::Item>()?;
        }
        Frag::Meta => {
            input.parse::<syn::Meta>()?;
        }
        Frag::Vis => {
            input.parse::<syn::Visibility>()?;
        }
        Frag::Stmt => parse_stmt(input)?,
        Frag::Tt | Frag::Ident | Frag::Lifetime | Frag::Literal | Frag::Block => {}
    }
    Ok(())
}

/// A statement without its trailing `;`: a `let` binding, an item, or an
/// expression.
fn parse_stmt(input: ParseStream) -> syn::Result<()> {
    if input.peek(Token![let]) {
        input.parse::<Token![let]>()?;
        syn::Pat::parse_multi_with_leading_vert(input)?;
        if input.peek(Token![:]) {
            input.parse::<Token![:]>()?;
            input.parse::<syn::Type>()?;
        }
        if input.peek(Token![=]) {
            input.parse::<Token![=]>()?;
            input.parse::<syn::Expr>()?;
            if input.peek(Token![else]) {
                input.parse::<Token![else]>()?;
                input.parse::<syn::Block>()?;
            }
        }
        return Ok(());
    }
    if input.fork().parse::<syn::Item>().is_ok() {
        input.parse::<syn::Item>()?;
        return Ok(());
    }
    input.parse::<syn::Expr>()?;
    Ok(())
}
