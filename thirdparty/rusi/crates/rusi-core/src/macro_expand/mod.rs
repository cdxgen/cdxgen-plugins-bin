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
    CratePrepass, InvocationTarget, MacroFilePrepass, MacroRef, MacroScopeTable, Pos, is_std_macro,
    prepass_from_parsed,
};

use proc_macro2::{TokenStream, TokenTree};

/// How deeply nested workspace macro invocations are expanded unless the
/// crate says otherwise: rustc's default `recursion_limit`. Token-tree
/// munchers that count or fold a list use one level per token, so a lower
/// value stops code that compiles. The token and step budgets, not this depth,
/// bound the work.
pub(crate) const DEFAULT_RECURSION_LIMIT: usize = 128;

/// The most a crate's `#![recursion_limit]` can raise the depth to. The
/// analysis thread has 16 MiB of stack, and 256 levels of nested expansion use
/// a small fraction of it.
pub(crate) const MAX_RECURSION_LIMIT: usize = 256;

/// Ceiling on the tokens one hand-written invocation may produce, summed
/// across every nested and sibling expansion. Depth alone does not bound a
/// macro that doubles its input per level. The largest invocation in the small
/// corpus and the fixture produces under 1,700 tokens, and expanding, parsing
/// and walking 50,000 tokens takes under 100 ms, so one invocation of a hostile
/// macro stays near that while real macros have a factor of 30 to spare. A
/// counting muncher over n tokens produces about n squared over 2 tokens in
/// all, so 50,000 also covers the 256 levels the deepest allowed recursion
/// limit permits.
pub(crate) const MAX_EXPANSION_TOKENS: usize = 50_000;

/// Ceiling on the expansion work in one source file, and in the whole
/// analysis. Work is the tokens an expansion produces plus a tenth of the
/// matcher steps it used. A hostile macro costs one invocation budget per
/// copy, so the per-invocation bound alone lets many copies add up to minutes.
/// The whole small corpus and the fixture together spend under 4,000 tokens
/// and 700 steps, a counting muncher at the deepest allowed recursion limit
/// about 85,000, so the file ceiling leaves real code a factor of several
/// hundred over the corpus and room for several of those, and the analysis
/// ceiling stops the worst case at about four seconds of work whatever the
/// number of copies or files. Which invocations the analysis-wide ceiling cuts
/// off depends on the order the files are analysed in, which only matters once
/// it is reached.
pub(crate) const MAX_FILE_EXPANSION_WORK: usize = 500_000;
pub(crate) const MAX_ANALYSIS_EXPANSION_WORK: usize = 2_000_000;

/// How many iterations one repetition may take in a match. rustc has no such
/// cap; the matcher's work grows with every iteration, so a cap keeps an
/// absurd input from stretching an expansion, and a hand-written macro input
/// does not come near it.
pub(crate) const MAX_REPETITION_ITERATIONS: usize = 16_384;

/// The step budget of one expansion. Every thread advance, every epsilon move
/// and every fragment parse (weighted by the tokens it reads) costs steps, and
/// the budget is shared by all the rules of the invocation. The most any
/// macro in the small corpus and the fixture used was 178 steps, and a
/// repetition that runs to its iteration cap costs under 200,000, so 250,000
/// leaves a legitimate match its worst case while a matcher and input that
/// rustc would reject are stopped within tens of milliseconds.
pub(crate) const MAX_MATCH_STEPS: usize = 250_000;

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
    /// Steps of the budget the expansion used.
    pub(crate) steps: usize,
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
                return Ok(Expansion {
                    tokens,
                    renamed,
                    steps: max_steps.saturating_sub(budget.remaining()),
                });
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

/// Expansion work spent so far in one analysis, shared by every thread that
/// analyses a file.
#[derive(Debug, Default)]
pub(crate) struct WorkLedger {
    spent: std::sync::atomic::AtomicUsize,
    reported: std::sync::atomic::AtomicBool,
}

impl Clone for WorkLedger {
    fn clone(&self) -> Self {
        use std::sync::atomic::Ordering::Relaxed;
        Self {
            spent: std::sync::atomic::AtomicUsize::new(self.spent.load(Relaxed)),
            reported: std::sync::atomic::AtomicBool::new(self.reported.load(Relaxed)),
        }
    }
}

impl WorkLedger {
    pub(crate) fn exhausted(&self) -> bool {
        self.spent.load(std::sync::atomic::Ordering::Relaxed) > MAX_ANALYSIS_EXPANSION_WORK
    }

    /// Adds `work` and returns whether the analysis is still within its ceiling.
    pub(crate) fn charge(&self, work: usize) -> bool {
        let before = self
            .spent
            .fetch_add(work, std::sync::atomic::Ordering::Relaxed);
        before.saturating_add(work) <= MAX_ANALYSIS_EXPANSION_WORK
    }

    /// True for the first caller only, so the ceiling is reported once.
    pub(crate) fn report_once(&self) -> bool {
        !self
            .reported
            .swap(true, std::sync::atomic::Ordering::Relaxed)
    }
}
