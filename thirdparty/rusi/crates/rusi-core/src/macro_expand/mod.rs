//! Workspace `macro_rules!`: collection, scoping and expansion.
//!
//! The stable backend used to stop at macro invocations: a definition body
//! was skipped and an invocation's tokens were recovered as Rust only when
//! they happened to parse. This module gives it the two halves it was
//! missing:
//!
//! * [`scope`] collects every `macro_rules!` definition in the analysed
//!   crates together with how each is in scope, and resolves the macro path
//!   written at a position;
//! * [`matcher`], [`transcriber`] and [`hygiene`] expand an invocation
//!   against the collected rules, so declarations, calls and flows inside a
//!   workspace macro come out as if the code had been written by hand.
//!
//! Dependency macros are not expanded (their source is only read with
//! `--deps`); the scope table still resolves their invocations to the owning
//! crate so the caller can record usage and call-graph evidence for them.
//!
//! rusi analyses untrusted source, so nothing here may panic or run without
//! bound on input that compiles. The module avoids `unwrap`, `expect`,
//! direct identifier construction and unchecked indexing on data that comes from the source,
//! and every loop that the input can lengthen is covered by a bound below.

mod hygiene;
mod matcher;
mod scope;
mod transcriber;

pub(crate) use hygiene::strip_suffixes;
use matcher::MatchError;
pub(crate) use scope::{
    CratePrepass, InvocationTarget, MacroFilePrepass, MacroRef, MacroScopeTable, Pos, prepass_file,
};

use proc_macro2::{TokenStream, TokenTree};

/// How deeply nested workspace macro invocations are expanded. Every level
/// costs a full parse and visitor pass, well beyond what rustc spends per
/// level, so this is half of rustc's default `recursion_limit` (128). Real
/// token-tree munchers end within a few dozen levels; a macro that recurses
/// forever is stopped here and reported.
pub(crate) const MAX_EXPANSION_DEPTH: usize = 64;

/// Ceiling on the tokens one hand-written invocation may produce, summed
/// across every nested and sibling expansion. Depth alone does not bound a
/// macro that doubles its input per level; one million tokens is several
/// megabytes of token trees, far above any hand-written macro's output and
/// small enough to fail fast on exponential growth.
pub(crate) const MAX_EXPANSION_TOKENS: usize = 1_000_000;

/// How many iterations one repetition may take in a match. rustc has no such
/// cap; the matcher's work grows with every iteration, so a cap keeps an
/// absurd input from stretching an expansion, and a hand-written macro input
/// does not come near it.
pub(crate) const MAX_REPETITION_ITERATIONS: usize = 16_384;

/// The step budget of one expansion. Every thread advance, every epsilon move
/// and every fragment parse (weighted by the tokens it reads) costs steps, and
/// the budget is shared by all the rules of the invocation. The most any
/// macro in the small corpus and the fixture uses is under 200 steps, and a
/// repetition that runs to its iteration cap costs about 130,000, so one
/// million leaves a legitimate match room for several such repetitions while
/// a matcher and input that rustc would reject are stopped within a few
/// milliseconds.
pub(crate) const MAX_MATCH_STEPS: usize = 1_000_000;

/// Nesting of groups the module reads, in definitions and in invocations.
/// Source that compiles nests far less; the bound keeps recursive reads of
/// adversarial source from exhausting the stack.
pub(super) const MAX_NESTING: usize = 64;

/// One `macro_rules!` rule, kept as token text so the table can be shared
/// across the analysis threads (`proc_macro2` types are not `Send`). The
/// patterns are parsed per invocation, on the analysing thread.
#[derive(Debug, Clone)]
pub(super) struct MacroRule {
    pub(super) matcher: String,
    pub(super) transcriber: String,
}

/// One `macro_rules!` definition found by the pre-pass.
#[derive(Debug, Clone)]
pub(crate) struct MacroDefinition {
    pub(crate) name: String,
    /// Module path of the defining file, relative to its crate root.
    pub(crate) module_path: Vec<String>,
    pub(crate) file_path: String,
    /// 1-based line and 0-based column of the macro's name token.
    pub(crate) line: usize,
    pub(crate) column: usize,
    /// `#[macro_export]` puts the macro at its crate root.
    pub(crate) exported: bool,
    /// Whether `pat` accepts a top-level or-pattern (edition 2021 and later).
    pub(crate) edition_2021: bool,
    /// The innermost block that holds the definition, as start and end
    /// positions; `None` for a definition at module level.
    pub(crate) block: Option<(Pos, Pos)>,
    pub(super) rules: Vec<MacroRule>,
}

impl MacroDefinition {
    /// The path evidence names this macro by: the crate root for an exported
    /// macro, the defining module plus the name otherwise. It matches the
    /// `kind: "macro"` declaration's `qualified_name`, so a consumer can join
    /// `expanded_from.macro` to the declaration.
    pub(crate) fn canonical_path(&self, crate_name: &str) -> String {
        let mut segments = vec![crate_name.to_string()];
        if !self.exported {
            segments.extend(self.module_path.iter().cloned());
        }
        segments.push(self.name.clone());
        segments.join("::")
    }

    /// The declaration signature: `macro_rules! name`, prefixed with the
    /// attribute when the macro is exported.
    pub(crate) fn signature(&self) -> String {
        if self.exported {
            format!("#[macro_export] macro_rules! {}", self.name)
        } else {
            format!("macro_rules! {}", self.name)
        }
    }
}

/// Why an expansion did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExpandError {
    /// No rule's matcher accepted the invocation tokens.
    NoRuleMatches,
    /// rustc's local ambiguity: more than one way to continue the match. rustc
    /// rejects such an invocation, so no crate that compiles has one.
    Ambiguous,
    /// The step budget of the expansion was spent.
    StepBudget,
    /// A repetition reached the iteration cap and no rule matched without it.
    IterationLimit,
    /// The definition could not be read as rules.
    Malformed(String),
    /// The invocation nests deeper than the module reads.
    TooDeep,
    /// A rule matched but could not be transcribed.
    Transcribe(String),
}

/// The result of an expansion.
#[derive(Debug)]
pub(crate) struct Expansion {
    pub(crate) tokens: TokenStream,
    /// Whether hygiene renamed any binding, so the report needs its suffixes
    /// removed.
    pub(crate) renamed: bool,
}

/// Expands `input` against `definition`'s rules in order and returns the first
/// matching rule's transcription. `$crate` becomes `crate_name`, and bindings
/// the transcriber writes are renamed with a suffix made from `invocation` so
/// that they cannot alias the caller's.
pub(crate) fn expand(
    definition: &MacroDefinition,
    crate_name: &str,
    input: TokenStream,
    invocation: &str,
) -> Result<Expansion, ExpandError> {
    expand_with_budget(definition, crate_name, input, invocation, MAX_MATCH_STEPS)
}

pub(crate) fn expand_with_budget(
    definition: &MacroDefinition,
    crate_name: &str,
    input: TokenStream,
    invocation: &str,
    max_steps: usize,
) -> Result<Expansion, ExpandError> {
    let trees: Vec<TokenTree> = input.into_iter().collect();
    let flat = matcher::FlatInput::new(&trees).ok_or(ExpandError::TooDeep)?;
    let mut budget = matcher::Budget::new(max_steps);
    let mut iteration_cap = false;
    let mut malformed: Option<String> = None;
    for rule in &definition.rules {
        let pattern = match rule
            .matcher
            .parse::<TokenStream>()
            .map_err(|error| error.to_string())
            .and_then(|stream| matcher::parse_matcher(stream, definition.edition_2021))
        {
            Ok(pattern) => pattern,
            Err(reason) => {
                malformed = Some(reason);
                continue;
            }
        };
        let compiled = matcher::compile(&pattern);
        match matcher::run(&compiled, &flat, &mut budget) {
            Err(error) => {
                return Err(match error {
                    MatchError::Ambiguous => ExpandError::Ambiguous,
                    MatchError::StepBudget => ExpandError::StepBudget,
                });
            }
            Ok(matcher::Matched::No { iteration_cap: hit }) => iteration_cap |= hit,
            Ok(matcher::Matched::Yes(bindings)) => {
                let mut template = rule
                    .transcriber
                    .parse::<TokenStream>()
                    .map_err(|error| error.to_string())
                    .and_then(transcriber::parse_template)
                    .map_err(ExpandError::Malformed)?;
                let renamed = hygiene::apply(&mut template, invocation);
                let tokens = transcriber::transcribe(&template, &bindings, crate_name)
                    .map_err(ExpandError::Transcribe)?;
                return Ok(Expansion { tokens, renamed });
            }
        }
    }
    if iteration_cap {
        Err(ExpandError::IterationLimit)
    } else if let Some(reason) = malformed {
        Err(ExpandError::Malformed(reason))
    } else {
        Err(ExpandError::NoRuleMatches)
    }
}

#[cfg(test)]
mod scope_tests;
#[cfg(test)]
mod tests;
