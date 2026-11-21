//! Hygiene for the bindings a transcriber introduces.
//!
//! rustc keeps a local variable written in a transcriber apart from a caller
//! variable of the same name. The expander gets the same effect by renaming
//! each binding the template writes literally, and its later uses, with a
//! suffix that is unique to the invocation. Only binding positions and the
//! single-segment uses that refer to them are renamed: a name after `::` or
//! `.`, a struct field or literal key, a macro name, an item name and a type
//! are never touched. Tokens that come from a metavariable keep the caller's
//! spelling because the template only holds `$name` for them.
//!
//! The recognition works on tokens, without a parser, so it relies on the
//! conventions rustc enforces by lint: bindings are `snake_case`, and type
//! and constructor names start with a capital letter.

use std::collections::BTreeSet;

use proc_macro2::{Delimiter, Literal, Punct, Spacing, TokenStream, TokenTree};

use super::transcriber::Tpl;

/// The marker that ends every renamed identifier. It is followed by the
/// invocation's number and removed again by [`strip_suffixes`].
pub(crate) const MARK: &str = "__rhyg";

/// Removes every renaming suffix from `text`, so reports show the names the
/// source wrote.
pub(crate) fn strip_suffixes(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains(MARK) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(MARK) {
        out.push_str(&rest[..at]);
        let after = &rest[at + MARK.len()..];
        let digits = after.chars().take_while(char::is_ascii_digit).count();
        rest = &after[digits..];
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
}

struct State {
    suffix: String,
    bound: BTreeSet<String>,
    renamed: bool,
}

/// Renames the template's bindings and their uses. Returns whether anything
/// was renamed.
pub(super) fn apply(template: &mut [Tpl], invocation: &str) -> bool {
    let mut state = State {
        suffix: format!("{MARK}{invocation}"),
        bound: BTreeSet::new(),
        renamed: false,
    };
    walk(template, &mut state, false);
    state.renamed
}

const KEYWORDS: &[&str] = &[
    "as", "async", "await", "box", "break", "const", "continue", "crate", "dyn", "else", "enum",
    "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move",
    "mut", "pub", "ref", "return", "self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while",
];

/// Macros whose string arguments are not format strings.
const NON_FORMAT_MACROS: &[&str] = &[
    "stringify",
    "concat",
    "include_str",
    "include_bytes",
    "include",
    "env",
    "option_env",
    "compile_error",
    "cfg",
];

/// Keywords after which an identifier is an item or type name.
const ITEM_KEYWORDS: &[&str] = &[
    "fn",
    "struct",
    "enum",
    "union",
    "trait",
    "type",
    "mod",
    "const",
    "static",
    "impl",
    "use",
    "as",
    "extern",
    "where",
    "dyn",
    "macro_rules",
];

/// Keywords after which a `|` starts a closure rather than a bitwise or.
const CLOSURE_PREFIX_KEYWORDS: &[&str] = &[
    "move", "return", "break", "in", "else", "async", "yield", "static",
];

fn ident_text(element: &Tpl) -> Option<String> {
    match element {
        Tpl::Tok(TokenTree::Ident(ident)) => Some(ident.to_string()),
        _ => None,
    }
}

fn punct(element: &Tpl) -> Option<(char, Spacing)> {
    match element {
        Tpl::Tok(TokenTree::Punct(punct)) => Some((punct.as_char(), punct.spacing())),
        _ => None,
    }
}

fn is_punct(element: Option<&Tpl>, c: char) -> bool {
    element.and_then(punct).is_some_and(|(found, _)| found == c)
}

fn base_name(text: &str) -> &str {
    text.strip_prefix("r#").unwrap_or(text)
}

/// A name that conventionally binds a value.
fn is_binding_name(text: &str) -> bool {
    let name = base_name(text);
    !KEYWORDS.contains(&name)
        && name != "_"
        && name
            .chars()
            .next()
            .is_some_and(|c| c == '_' || c.is_lowercase())
}

fn starts_uppercase(text: &str) -> bool {
    base_name(text)
        .chars()
        .next()
        .is_some_and(char::is_uppercase)
}

/// `level[at]` is the second colon of a `::`.
fn follows_path_separator(level: &[Tpl], at: usize) -> bool {
    at >= 2
        && is_punct(level.get(at - 1), ':')
        && level
            .get(at - 2)
            .and_then(punct)
            .is_some_and(|(c, spacing)| c == ':' && spacing == Spacing::Joint)
}

/// `level[at]` starts a `::`.
fn precedes_path_separator(level: &[Tpl], at: usize) -> bool {
    level
        .get(at)
        .and_then(punct)
        .is_some_and(|(c, spacing)| c == ':' && spacing == Spacing::Joint)
        && is_punct(level.get(at + 1), ':')
}

/// `level[at]` is a `:` that is neither half of a `::`.
fn is_single_colon(level: &[Tpl], at: usize) -> bool {
    is_punct(level.get(at), ':')
        && !precedes_path_separator(level, at)
        && !follows_path_separator(level, at)
}

fn is_single_equals(level: &[Tpl], at: usize) -> bool {
    let Some(('=', spacing)) = level.get(at).and_then(punct) else {
        return false;
    };
    // Not `==` or `=>`.
    if spacing == Spacing::Joint
        && matches!(level.get(at + 1).and_then(punct), Some(('=' | '>', _)))
    {
        return false;
    }
    // Not the tail of `==`, `!=`, `<=`, `+=` and the like.
    let continues_operator = at
        .checked_sub(1)
        .and_then(|previous| level.get(previous))
        .and_then(punct)
        .is_some_and(|(c, spacing)| spacing == Spacing::Joint && "=!<>+-*/%^&|".contains(c));
    !continues_operator
}

fn is_fat_arrow(level: &[Tpl], at: usize) -> bool {
    level
        .get(at)
        .and_then(punct)
        .is_some_and(|(c, spacing)| c == '=' && spacing == Spacing::Joint)
        && is_punct(level.get(at + 1), '>')
}

fn rename_token(element: &mut Tpl, state: &mut State) -> bool {
    let Tpl::Tok(TokenTree::Ident(ident)) = element else {
        return false;
    };
    let text = ident.to_string();
    let renamed = format!("{}{}", base_name(&text), state.suffix);
    // Lexing the text reports a bad identifier as an error, where a direct
    // constructor would panic.
    let Ok(stream) = renamed.parse::<TokenStream>() else {
        return false;
    };
    let mut trees = stream.into_iter();
    let (Some(TokenTree::Ident(mut fresh)), None) = (trees.next(), trees.next()) else {
        return false;
    };
    fresh.set_span(ident.span());
    *ident = fresh;
    state.renamed = true;
    true
}

fn bind(element: &mut Tpl, state: &mut State) {
    let Some(text) = ident_text(element) else {
        return;
    };
    let name = base_name(&text).to_string();
    if rename_token(element, state) {
        state.bound.insert(name);
    }
}

/// Renames the bindings in a pattern, wherever the pattern appears.
fn rename_pattern(items: &mut [Tpl], state: &mut State) {
    let mut k = 0usize;
    while k < items.len() {
        let decision = match &items[k] {
            Tpl::Tok(TokenTree::Ident(ident)) => {
                let text = ident.to_string();
                let before_ok = !(follows_path_separator(items, k)
                    || is_punct(k.checked_sub(1).and_then(|p| items.get(p)), '.')
                    || is_punct(k.checked_sub(1).and_then(|p| items.get(p)), '\''));
                let after_ok = !(precedes_path_separator(items, k + 1)
                    || matches!(
                        items.get(k + 1),
                        Some(Tpl::Group(Delimiter::Parenthesis | Delimiter::Brace, ..))
                    )
                    || is_punct(items.get(k + 1), '!'));
                is_binding_name(&text) && before_ok && after_ok
            }
            _ => false,
        };
        if decision {
            bind(&mut items[k], state);
        } else {
            match &mut items[k] {
                Tpl::Group(Delimiter::Brace, _, children) => {
                    rename_fields(children, true, state);
                }
                Tpl::Group(_, _, children) => rename_pattern(children, state),
                Tpl::Rep { body, .. } => rename_pattern(body, state),
                _ => {}
            }
        }
        k += 1;
    }
}

/// Handles the body of a struct pattern or struct literal, where a field
/// written as just its name is both the field and a variable.
fn rename_fields(children: &mut Vec<Tpl>, pattern: bool, state: &mut State) {
    let old = std::mem::take(children);
    let mut field: Vec<Tpl> = Vec::new();
    let mut out: Vec<Tpl> = Vec::new();
    let flush = |field: &mut Vec<Tpl>, out: &mut Vec<Tpl>, state: &mut State| {
        let mut taken = std::mem::take(field);
        if let Some(colon) = (0..taken.len()).find(|&at| is_single_colon(&taken, at)) {
            let value = &mut taken[colon + 1..];
            if pattern {
                rename_pattern(value, state);
            } else {
                walk(value, state, false);
            }
            out.extend(taken);
            return;
        }
        let (modifiers, name) = split_shorthand(&taken);
        if let Some(name) = name {
            let text = ident_text(&taken[name]).unwrap_or_default();
            let hit = if pattern {
                is_binding_name(&text)
            } else {
                state.bound.contains(base_name(&text))
            };
            if hit && let Some(Tpl::Tok(TokenTree::Ident(original))) = taken.get(name).cloned() {
                let mut renamed = taken[name].clone();
                if pattern {
                    bind(&mut renamed, state);
                } else {
                    rename_token(&mut renamed, state);
                }
                let colon = Tpl::Tok(TokenTree::Punct(Punct::new(':', Spacing::Alone)));
                out.push(Tpl::Tok(TokenTree::Ident(original)));
                out.push(colon);
                out.extend(taken[..modifiers].iter().cloned());
                out.push(renamed);
                return;
            }
        }
        if pattern {
            rename_pattern(&mut taken, state);
        } else {
            walk(&mut taken, state, false);
        }
        out.extend(taken);
    };
    for element in old {
        if is_punct(Some(&element), ',') {
            flush(&mut field, &mut out, state);
            out.push(element);
        } else {
            field.push(element);
        }
    }
    flush(&mut field, &mut out, state);
    *children = out;
}

/// For a field of the form `[ref] [mut] name`, the number of leading
/// modifiers and the index of the name.
fn split_shorthand(field: &[Tpl]) -> (usize, Option<usize>) {
    let mut modifiers = 0usize;
    for element in field {
        match ident_text(element).as_deref() {
            Some("ref" | "mut") => modifiers += 1,
            _ => break,
        }
    }
    if field.len() == modifiers + 1 && ident_text(&field[modifiers]).is_some() {
        (modifiers, Some(modifiers))
    } else {
        (modifiers, None)
    }
}

/// Whether the `for` at `level[at]` starts a loop, and the index of its `in`.
fn for_loop_in(level: &[Tpl], at: usize) -> Option<usize> {
    if is_punct(level.get(at + 1), '<') {
        return None;
    }
    for (offset, element) in level.iter().enumerate().skip(at + 1) {
        match element {
            Tpl::Group(Delimiter::Brace, ..) => return None,
            _ if is_punct(Some(element), ';') => return None,
            _ if ident_text(element).as_deref() == Some("in") => return Some(offset),
            _ => {}
        }
    }
    None
}

/// The index where a `let` pattern ends: at `=`, a type ascription, `;` or
/// `else`.
fn let_pattern_end(level: &[Tpl], at: usize) -> usize {
    (at + 1..level.len())
        .find(|&k| {
            is_single_equals(level, k)
                || is_single_colon(level, k)
                || is_punct(level.get(k), ';')
                || ident_text(&level[k]).as_deref() == Some("else")
        })
        .unwrap_or(level.len())
}

/// Whether a `|` at `level[at]` starts a closure parameter list.
fn starts_closure(level: &[Tpl], at: usize) -> bool {
    match at.checked_sub(1).and_then(|previous| level.get(previous)) {
        None => true,
        Some(Tpl::Tok(TokenTree::Punct(_))) => true,
        Some(Tpl::Tok(TokenTree::Ident(ident))) => {
            CLOSURE_PREFIX_KEYWORDS.contains(&ident.to_string().as_str())
        }
        _ => false,
    }
}

/// Whether the brace group at `level[at]` holds the arms of a `match`.
fn is_match_arms(level: &[Tpl], at: usize) -> bool {
    for element in level[..at].iter().rev().take(64) {
        if matches!(element, Tpl::Group(Delimiter::Brace, ..)) || is_punct(Some(element), ';') {
            return false;
        }
        if ident_text(element).as_deref() == Some("match") {
            return true;
        }
    }
    false
}

fn is_struct_literal_group(level: &[Tpl], at: usize) -> bool {
    let Some(name) = at
        .checked_sub(1)
        .and_then(|previous| level.get(previous))
        .and_then(ident_text)
    else {
        return false;
    };
    if !(starts_uppercase(&name) || name == "Self") {
        return false;
    }
    // `if FLAG { x }` is a block, not a struct literal.
    !matches!(
        at.checked_sub(2)
            .and_then(|before| level.get(before))
            .and_then(ident_text)
            .as_deref(),
        Some("if" | "while" | "match" | "in")
    )
}

/// The attribute or `use` or `fn` item starting at `level[at]` is skipped
/// whole: attributes and imports hold no variables, and a nested function is
/// its own scope that no caller variable can reach.
fn item_end(level: &[Tpl], at: usize) -> Option<usize> {
    if is_punct(level.get(at), '#') {
        let mut next = at + 1;
        if is_punct(level.get(next), '!') {
            next += 1;
        }
        return matches!(level.get(next), Some(Tpl::Group(Delimiter::Bracket, ..))).then_some(next);
    }
    match ident_text(&level[at]).as_deref() {
        Some("use") => (at..level.len()).find(|&k| is_punct(level.get(k), ';')),
        Some("fn") if matches!(level.get(at + 1), Some(Tpl::Tok(TokenTree::Ident(_)))) => {
            (at..level.len()).find(|&k| {
                matches!(level[k], Tpl::Group(Delimiter::Brace, ..)) || is_punct(level.get(k), ';')
            })
        }
        _ => None,
    }
}

fn walk(level: &mut [Tpl], state: &mut State, in_format: bool) {
    let mut j = 0usize;
    while j < level.len() {
        if let Some(end) = item_end(level, j) {
            j = end + 1;
            continue;
        }
        let keyword = ident_text(&level[j]);
        match keyword.as_deref() {
            Some("let") => {
                let end = let_pattern_end(level, j);
                rename_pattern(&mut level[j + 1..end], state);
                j = end;
                continue;
            }
            Some("for") => {
                if let Some(in_at) = for_loop_in(level, j) {
                    rename_pattern(&mut level[j + 1..in_at], state);
                    j = in_at + 1;
                    continue;
                }
            }
            _ => {}
        }
        if let Some((c, spacing)) = punct(&level[j]) {
            if c == '|' && !is_punct(level.get(j + 1), '=') {
                let double = spacing == Spacing::Joint && is_punct(level.get(j + 1), '|');
                if double {
                    // `||`: an empty parameter list or a logical or, and
                    // neither binds anything.
                    j += 2;
                    continue;
                }
                if starts_closure(level, j)
                    && let Some(close) = (j + 1..level.len()).find(|&k| is_punct(level.get(k), '|'))
                {
                    rename_closure_parameters(&mut level[j + 1..close], state);
                    j = close + 1;
                    continue;
                }
            }
            j += 1;
            continue;
        }
        match &level[j] {
            Tpl::Tok(TokenTree::Ident(ident)) => {
                let text = ident.to_string();
                if state.bound.contains(base_name(&text)) && is_use_position(level, j) {
                    rename_token(&mut level[j], state);
                }
            }
            Tpl::Tok(TokenTree::Literal(_)) if in_format => {
                if let Tpl::Tok(TokenTree::Literal(literal)) = &level[j]
                    && let Some(rewritten) = rewrite_format_string(literal, state)
                {
                    level[j] = Tpl::Tok(TokenTree::Literal(rewritten));
                }
            }
            Tpl::Group(delimiter, ..) => {
                let delimiter = *delimiter;
                let macro_name = (j >= 2 && is_punct(level.get(j - 1), '!'))
                    .then(|| ident_text(&level[j - 2]))
                    .flatten();
                let format_args = macro_name
                    .as_deref()
                    .is_some_and(|name| !NON_FORMAT_MACROS.contains(&name));
                let is_arms = delimiter == Delimiter::Brace && is_match_arms(level, j);
                let is_literal =
                    delimiter == Delimiter::Brace && !is_arms && is_struct_literal_group(level, j);
                if let Tpl::Group(_, _, children) = &mut level[j] {
                    if is_arms {
                        walk_arms(children, state);
                    } else if is_literal {
                        rename_fields(children, false, state);
                    } else {
                        walk(children, state, format_args);
                    }
                }
            }
            Tpl::Rep { .. } => {
                if let Tpl::Rep { body, .. } = &mut level[j] {
                    walk(body, state, in_format);
                }
            }
            _ => {}
        }
        j += 1;
    }
}

/// Whether the identifier at `level[at]` is a single-segment use of a
/// variable, as opposed to a field, path segment, macro or item name, key or
/// lifetime.
fn is_use_position(level: &[Tpl], at: usize) -> bool {
    if let Some(previous) = at.checked_sub(1).and_then(|previous| level.get(previous)) {
        if is_punct(Some(previous), '.') || is_punct(Some(previous), '\'') {
            return false;
        }
        if follows_path_separator(level, at) {
            return false;
        }
        if let Some(text) = ident_text(previous)
            && ITEM_KEYWORDS.contains(&text.as_str())
        {
            return false;
        }
    }
    if precedes_path_separator(level, at + 1) {
        return false;
    }
    if is_punct(level.get(at + 1), '!') && matches!(level.get(at + 2), Some(Tpl::Group(..))) {
        return false;
    }
    // A name followed by a single colon is a struct key, a field, a
    // parameter or a named argument, never a use.
    !is_single_colon(level, at + 1)
}

fn rename_closure_parameters(parameters: &mut [Tpl], state: &mut State) {
    let mut start = 0usize;
    while start <= parameters.len() {
        let end = (start..parameters.len())
            .find(|&k| is_punct(parameters.get(k), ','))
            .unwrap_or(parameters.len());
        let pattern_end = (start..end)
            .find(|&k| is_single_colon(parameters, k))
            .unwrap_or(end);
        rename_pattern(&mut parameters[start..pattern_end], state);
        start = end + 1;
    }
}

/// Renames the bindings of each arm of a `match` and walks the guards and
/// bodies.
fn walk_arms(arms: &mut [Tpl], state: &mut State) {
    let mut k = 0usize;
    while k < arms.len() {
        let Some(arrow) = (k..arms.len()).find(|&at| is_fat_arrow(arms, at)) else {
            walk(&mut arms[k..], state, false);
            return;
        };
        let guard = (k..arrow).find(|&at| ident_text(&arms[at]).as_deref() == Some("if"));
        let pattern_end = guard.unwrap_or(arrow);
        rename_pattern(&mut arms[k..pattern_end], state);
        if guard.is_some() {
            walk(&mut arms[pattern_end..arrow], state, false);
        }
        let body_start = arrow + 2;
        let body_end = if matches!(arms.get(body_start), Some(Tpl::Group(Delimiter::Brace, ..))) {
            body_start + 1
        } else {
            (body_start..arms.len())
                .find(|&at| is_punct(arms.get(at), ','))
                .unwrap_or(arms.len())
        };
        let body_end = body_end.min(arms.len());
        walk(&mut arms[body_start.min(body_end)..body_end], state, false);
        k = body_end;
        if is_punct(arms.get(k), ',') {
            k += 1;
        }
    }
}

/// Rewrites `{name}` and `{name:...}` in a format string for renamed names.
fn rewrite_format_string(literal: &Literal, state: &State) -> Option<Literal> {
    let text = literal.to_string();
    if !(text.starts_with('"') || text.starts_with("r\"") || text.starts_with("r#")) {
        return None;
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len() + 16);
    let mut changed = false;
    let mut i = 0usize;
    while i < chars.len() {
        out.push(chars[i]);
        if chars[i] == '{' {
            if chars.get(i + 1) == Some(&'{') {
                out.push('{');
                i += 2;
                continue;
            }
            let start = i + 1;
            let mut end = start;
            while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
                end += 1;
            }
            let name: String = chars[start..end].iter().collect();
            let terminated = matches!(chars.get(end), Some('}' | ':'));
            if terminated && state.bound.contains(&name) && is_binding_name(&name) {
                out.push_str(&name);
                out.push_str(&state.suffix);
                changed = true;
                i = end;
                continue;
            }
        }
        i += 1;
    }
    if !changed {
        return None;
    }
    let stream = out.parse::<TokenStream>().ok()?;
    let mut trees = stream.into_iter();
    match (trees.next(), trees.next()) {
        (Some(TokenTree::Literal(mut rewritten)), None) => {
            rewritten.set_span(literal.span());
            Some(rewritten)
        }
        _ => None,
    }
}
