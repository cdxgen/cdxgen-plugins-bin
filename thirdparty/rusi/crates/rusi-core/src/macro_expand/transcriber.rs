//! The `macro_rules!` transcriber: parses a rule's right-hand side into a
//! template and substitutes the matcher's bindings into it.

use proc_macro2::{Delimiter, Group, Punct, Spacing, Span, TokenStream, TokenTree};

use super::MAX_NESTING;
use super::matcher::{Binding, Bindings, Frag, read_repetition_tail, token_at};

/// One element of a parsed transcriber.
#[derive(Debug, Clone)]
pub(super) enum Tpl {
    /// A token written literally: an identifier, a literal or a punctuation
    /// character.
    Tok(TokenTree),
    Group(Delimiter, Span, Vec<Tpl>),
    /// `$name`
    Var(String),
    /// `$crate`
    DollarCrate,
    Rep {
        body: Vec<Tpl>,
        /// The separator's trees, repeated between iterations.
        sep: Option<Vec<TokenTree>>,
    },
}

/// Parses a transcriber. A `$name: Type` is a metavariable followed by a type,
/// because a fragment specifier only exists in a matcher.
pub(super) fn parse_template(stream: TokenStream) -> Result<Vec<Tpl>, String> {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    parse_seq(&trees, 0)
}

fn parse_seq(trees: &[TokenTree], depth: usize) -> Result<Vec<Tpl>, String> {
    if depth > MAX_NESTING {
        return Err("transcriber nesting is too deep".to_string());
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < trees.len() {
        match &trees[i] {
            TokenTree::Group(group) => {
                let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                out.push(Tpl::Group(
                    group.delimiter(),
                    group.span(),
                    parse_seq(&inner, depth + 1)?,
                ));
                i += 1;
            }
            TokenTree::Punct(punct) if punct.as_char() == '$' => match trees.get(i + 1) {
                Some(TokenTree::Ident(name)) if name == "crate" => {
                    out.push(Tpl::DollarCrate);
                    i += 2;
                }
                Some(TokenTree::Ident(name)) => {
                    out.push(Tpl::Var(name.to_string()));
                    i += 2;
                }
                Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis => {
                    let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                    let body = parse_seq(&inner, depth + 1)?;
                    let (sep, _, used) = read_repetition_tail(trees, i + 2)?;
                    let sep = match sep {
                        Some(_) => {
                            // Keep the separator's original trees.
                            let span = token_at(trees, i + 2).map_or(1, |(span, _)| span);
                            Some(trees[i + 2..i + 2 + span].to_vec())
                        }
                        None => None,
                    };
                    out.push(Tpl::Rep { body, sep });
                    i += 2 + used;
                }
                _ => {
                    out.push(Tpl::Tok(trees[i].clone()));
                    i += 1;
                }
            },
            other => {
                out.push(Tpl::Tok(other.clone()));
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Every metavariable name a template mentions, nested repetitions included.
fn variables(template: &[Tpl], out: &mut Vec<String>) {
    for element in template {
        match element {
            Tpl::Var(name) => out.push(name.clone()),
            Tpl::Group(_, _, inner) => variables(inner, out),
            Tpl::Rep { body, .. } => variables(body, out),
            Tpl::Tok(_) | Tpl::DollarCrate => {}
        }
    }
}

/// Follows `indexes` down a binding: every repetition level the transcriber
/// is inside selects one iteration, and a binding that is shallower than the
/// current level stays as it is.
fn lookup<'b>(bindings: &'b Bindings, name: &str, indexes: &[usize]) -> Option<&'b Binding> {
    let mut current = bindings.get(name)?;
    for &index in indexes {
        match current {
            Binding::Seq(items) => current = items.get(index)?,
            Binding::Leaf { .. } => break,
        }
    }
    Some(current)
}

/// An identifier token for `name`. Text that is not an identifier is reported
/// by `parse` as an error, so no input can reach a panicking constructor.
fn ident_from_text(name: &str, span: Span) -> Option<TokenTree> {
    let stream = name.parse::<TokenStream>().ok()?;
    let mut trees = stream.into_iter();
    match (trees.next(), trees.next()) {
        (Some(TokenTree::Ident(mut ident)), None) => {
            ident.set_span(span);
            Some(TokenTree::Ident(ident))
        }
        _ => None,
    }
}

/// The path root `$crate` stands for. A crate name that is not an identifier
/// falls back to `crate`.
fn crate_root(name: &str) -> Result<TokenTree, String> {
    ident_from_text(name, Span::call_site())
        .or_else(|| ident_from_text("crate", Span::call_site()))
        .ok_or_else(|| "`$crate` could not be spelled".to_string())
}

/// Substitutes `bindings` into `template`. `$crate` becomes `crate_name`.
pub(super) fn transcribe(
    template: &[Tpl],
    bindings: &Bindings,
    crate_name: &str,
) -> Result<TokenStream, String> {
    let mut out = Vec::new();
    let mut indexes = Vec::new();
    emit(template, bindings, crate_name, &mut indexes, &mut out)?;
    Ok(out.into_iter().collect())
}

fn emit(
    template: &[Tpl],
    bindings: &Bindings,
    crate_name: &str,
    indexes: &mut Vec<usize>,
    out: &mut Vec<TokenTree>,
) -> Result<(), String> {
    for element in template {
        match element {
            Tpl::Tok(tree) => out.push(tree.clone()),
            Tpl::DollarCrate => out.push(crate_root(crate_name)?),
            Tpl::Group(delimiter, span, inner) => {
                let mut body = Vec::new();
                emit(inner, bindings, crate_name, indexes, &mut body)?;
                let mut group = Group::new(*delimiter, body.into_iter().collect());
                group.set_span(*span);
                out.push(TokenTree::Group(group));
            }
            Tpl::Var(name) => match lookup(bindings, name, indexes) {
                Some(Binding::Leaf { trees, frag }) => push_fragment(trees, *frag, out),
                Some(Binding::Seq(_)) => {
                    return Err(format!(
                        "`${name}` is still repeating at this depth of the transcriber"
                    ));
                }
                None => {
                    // Not a matcher variable, so it was never a metavariable.
                    out.push(TokenTree::Punct(Punct::new('$', Spacing::Alone)));
                    out.extend(ident_from_text(name, Span::call_site()));
                }
            },
            Tpl::Rep { body, sep } => {
                let mut names = Vec::new();
                variables(body, &mut names);
                let mut count: Option<usize> = None;
                for name in &names {
                    if let Some(Binding::Seq(items)) = lookup(bindings, name, indexes) {
                        match count {
                            None => count = Some(items.len()),
                            Some(existing) if existing != items.len() => {
                                return Err(format!(
                                    "repetition counts differ: `${name}` has {} and another \
                                     variable has {existing}",
                                    items.len()
                                ));
                            }
                            Some(_) => {}
                        }
                    }
                }
                let Some(count) = count else {
                    return Err("a repetition in the transcriber uses no repeating \
                                metavariable"
                        .to_string());
                };
                for step in 0..count {
                    if step > 0
                        && let Some(separator) = sep
                    {
                        out.extend(separator.iter().cloned());
                    }
                    indexes.push(step);
                    let result = emit(body, bindings, crate_name, indexes, out);
                    indexes.pop();
                    result?;
                }
            }
        }
    }
    Ok(())
}

/// Splices a matched fragment. A multi-token expression keeps its grouping,
/// as rustc keeps an `expr` metavariable as one unit, so `$e * 2` does not
/// re-associate `a + b * 2`.
fn push_fragment(trees: &[TokenTree], frag: Frag, out: &mut Vec<TokenTree>) {
    if frag == Frag::Expr && trees.len() > 1 {
        let group = Group::new(Delimiter::None, trees.iter().cloned().collect());
        out.push(TokenTree::Group(group));
    } else {
        out.extend(trees.iter().cloned());
    }
}
