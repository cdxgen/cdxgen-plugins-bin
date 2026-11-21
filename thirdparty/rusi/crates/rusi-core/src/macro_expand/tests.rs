//! Unit tests for the matcher, the transcriber, hygiene and the bounds.

use std::time::{Duration, Instant};

use proc_macro2::TokenStream;

use super::*;

fn definition_with(body: &str, edition_2021: bool) -> MacroDefinition {
    let item: syn::ItemMacro =
        syn::parse_str(&format!("macro_rules! m {{ {body} }}")).expect("test macro parses");
    MacroDefinition {
        name: "m".to_string(),
        module_path: Vec::new(),
        file_path: "src/lib.rs".to_string(),
        line: 1,
        column: 0,
        exported: false,
        edition_2021,
        block: None,
        rules: scope::parse_rules(&item.mac.tokens).expect("test rules parse"),
    }
}

fn definition(body: &str) -> MacroDefinition {
    definition_with(body, true)
}

fn tokens(source: &str) -> TokenStream {
    source.parse().expect("test tokens lex")
}

/// Removes all whitespace so comparisons ignore token spacing.
fn squash(stream: &TokenStream) -> String {
    stream
        .to_string()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

fn expand_ok(body: &str, input: &str) -> String {
    match expand(&definition(body), "krate", tokens(input), "7") {
        Ok(expansion) => squash(&expansion.tokens),
        Err(error) => panic!("expected `{input}` to expand, got {error:?}"),
    }
}

fn expand_err(body: &str, input: &str) -> ExpandError {
    match expand(&definition(body), "krate", tokens(input), "7") {
        Ok(expansion) => panic!("expected an error, got `{}`", squash(&expansion.tokens)),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// Fragment specifiers
// ---------------------------------------------------------------------------

#[test]
fn ident_and_expr_and_ty_fragments() {
    let body = "($n:ident, $e:expr, $t:ty) => { fn $n() -> $t { $e } };";
    assert_eq!(
        expand_ok(body, "answer, 40 + 2, u32"),
        "fnanswer()->u32{40+2}"
    );
    // `_` is not an identifier.
    assert_eq!(expand_err(body, "_, 1, u8"), ExpandError::NoRuleMatches);
}

#[test]
fn literal_accepts_negative_numbers_and_booleans() {
    let body = "($l:literal) => { const X: () = { let _ = $l; }; };";
    assert!(expand_ok(body, "-1").contains("-1"));
    assert!(expand_ok(body, "true").contains("true"));
    assert!(expand_ok(body, "false").contains("false"));
    assert!(expand_ok(body, "\"text\"").contains("\"text\""));
    assert!(expand_ok(body, "-2.5").contains("-2.5"));
    // An identifier is not a literal; neither is a bare minus.
    assert_eq!(expand_err(body, "name"), ExpandError::NoRuleMatches);
    assert_eq!(expand_err(body, "-"), ExpandError::NoRuleMatches);
}

#[test]
fn tt_takes_joint_punctuation_and_lifetimes_as_one_tree() {
    let body = "($a:tt $b:tt) => { [$a | $b] };";
    assert_eq!(expand_ok(body, "+= x"), "[+=|x]");
    assert_eq!(expand_ok(body, "== y"), "[==|y]");
    assert_eq!(expand_ok(body, "-> z"), "[->|z]");
    assert_eq!(expand_ok(body, ":: w"), "[::|w]");
    assert_eq!(expand_ok(body, "'a b"), "['a|b]");
    assert_eq!(expand_ok(body, "(1 2) {3}"), "[(12)|{3}]");
    // Two trees are not three.
    assert_eq!(expand_err(body, "a b c"), ExpandError::NoRuleMatches);
    // A `tt` never takes half of a joint operator.
    let single = "($a:tt) => { $a };";
    assert_eq!(expand_ok(single, ">>="), ">>=");
}

#[test]
fn pat_takes_top_level_or_patterns_from_edition_2021() {
    let body = "($p:pat) => { match v { $p => 1, _ => 0 } };";
    assert!(expand_ok(body, "Some(1) | None").contains("Some(1)|None=>1"));
    // `pat_param` and `pat` before 2021 stop at the `|`.
    let old = definition_with("($p:pat | $q:pat) => { ($p, $q) };", false);
    let expansion = expand(&old, "krate", tokens("Some(1) | None"), "1").expect("2018 pat");
    assert_eq!(squash(&expansion.tokens), "(Some(1),None)");
    let param = definition("($p:pat_param | $q:pat_param) => { ($p, $q) };");
    let expansion = expand(&param, "krate", tokens("A | B"), "1").expect("pat_param");
    assert_eq!(squash(&expansion.tokens), "(A,B)");
    // In 2021 the same two-pattern matcher is ambiguous with `$p:pat`.
    let modern = definition("($p:pat | $q:pat) => { ($p, $q) };");
    assert!(expand(&modern, "krate", tokens("A | B"), "1").is_err());
}

#[test]
fn stmt_stops_before_the_semicolon_separator() {
    let body = "($($s:stmt);* $(;)?) => { fn f() { $($s;)* } };";
    assert_eq!(
        expand_ok(body, "let a = 1; let b = 2; foo()"),
        "fnf(){leta=1;letb=2;foo();}"
    );
    assert_eq!(expand_ok(body, "let a = 1;"), "fnf(){leta=1;}");
    assert_eq!(expand_ok(body, ""), "fnf(){}");
}

#[test]
fn vis_may_match_nothing_including_at_the_end() {
    let body = "($v:vis struct $n:ident;) => { $v struct $n; };";
    assert_eq!(expand_ok(body, "pub struct A;"), "pubstructA;");
    assert_eq!(
        expand_ok(body, "pub(crate) struct B;"),
        "pub(crate)structB;"
    );
    assert_eq!(expand_ok(body, "struct C;"), "structC;");
    let alone = "($v:vis) => { $v fn f() {} };";
    assert_eq!(expand_ok(alone, ""), "fnf(){}");
    assert_eq!(expand_ok(alone, "pub"), "pubfnf(){}");
    // A visibility is not an arbitrary parenthesized group after `pub`.
    let tuple = "($v:vis ($t:ty)) => { $v struct S($t); };";
    assert_eq!(expand_ok(tuple, "pub (u8)"), "pubstructS(u8);");
}

#[test]
fn remaining_fragments_match_what_rustc_accepts() {
    assert_eq!(
        expand_ok("($b:block) => { fn f() $b };", "{ 1 + 1 }"),
        "fnf(){1+1}"
    );
    assert_eq!(
        expand_ok("($i:item) => { $i };", "struct S { a: u8 }"),
        "structS{a:u8}"
    );
    assert_eq!(
        expand_ok("($m:meta) => { #[$m] struct S; };", "derive(Debug)"),
        "#[derive(Debug)]structS;"
    );
    assert_eq!(
        expand_ok("($p:path) => { let _ = $p::new(); };", "std::vec::Vec"),
        "let_=std::vec::Vec::new();"
    );
    assert_eq!(
        expand_ok("($l:lifetime) => { fn f<$l>(x: &$l u8) {} };", "'a"),
        "fnf<'a>(x:&'au8){}"
    );
    assert_eq!(
        expand_err("($b:block) => {};", "1"),
        ExpandError::NoRuleMatches
    );
    assert_eq!(
        expand_err("($l:lifetime) => {};", "a"),
        ExpandError::NoRuleMatches
    );
}

#[test]
fn expr_fragments_keep_their_grouping() {
    // `$e * 2` must not re-associate `a + b * 2`: the expression stays one
    // operand, as a grouped expression in the parsed result.
    let def = definition("($e:expr) => { $e * 2 };");
    let expansion = expand(&def, "krate", tokens("a + b"), "1").expect("expands");
    let parsed: syn::Expr = syn::parse2(expansion.tokens).expect("parses");
    let syn::Expr::Binary(product) = parsed else {
        panic!("expected a product");
    };
    assert!(matches!(product.op, syn::BinOp::Mul(_)));
    assert!(matches!(
        *product.left,
        syn::Expr::Group(_) | syn::Expr::Paren(_)
    ));
    // A single token needs no grouping.
    assert_eq!(expand_ok("($e:expr) => { $e * 2 };", "a"), "a*2");
}

// ---------------------------------------------------------------------------
// Repetitions and separators
// ---------------------------------------------------------------------------

#[test]
fn inner_optional_that_matches_zero_times_inside_an_outer_repetition() {
    let body = "($( $name:ident $(: $ty:ty)? ),*) => { $( fn $name() $(-> $ty)? {} )* };";
    assert_eq!(expand_ok(body, "a: u8, b"), "fna()->u8{}fnb(){}");
    assert_eq!(
        expand_ok(body, "a, b: u16, c"),
        "fna(){}fnb()->u16{}fnc(){}"
    );
    assert_eq!(expand_ok(body, ""), "");
    // A starred inner repetition that matches zero times as well.
    let star = "($( $n:ident $( + $m:ident )* );*) => { $( [$n $( $m )*] )* };";
    assert_eq!(expand_ok(star, "a + b + c; d; e + f"), "[abc][d][ef]");
}

#[test]
fn multi_token_separators_in_matchers_and_transcribers() {
    let path = "($($seg:ident)::+) => { $($seg)::+() };";
    assert_eq!(expand_ok(path, "crate::sink_b"), "crate::sink_b()");
    assert_eq!(expand_ok(path, "a::b::c"), "a::b::c()");
    let arrows = "($($k:ident => $v:expr),*) => { [$( ($k, $v) ),*] };";
    assert_eq!(expand_ok(arrows, "a => 1, b => 2"), "[(a,1),(b,2)]");
    let and = "($($c:ident)&&+) => { $($c)&&+ };";
    assert_eq!(expand_ok(and, "x && y && z"), "x&&y&&z");
    let thin = "($($t:ident)->+) => { $($t)->+ };";
    assert_eq!(expand_ok(thin, "a -> b"), "a->b");
    // The separator is one token: `=` and `>` apart are not `=>`.
    let strict = "($a:ident => $b:ident) => { ($a, $b) };";
    assert_eq!(expand_err(strict, "x = > y"), ExpandError::NoRuleMatches);
    assert_eq!(expand_ok(strict, "x => y"), "(x,y)");
}

#[test]
fn trailing_separator_options_and_one_or_more() {
    let body = "($($x:expr),+ $(,)?) => { [$($x),+] };";
    assert_eq!(expand_ok(body, "1, 2, 3"), "[1,2,3]");
    assert_eq!(expand_ok(body, "1, 2, 3,"), "[1,2,3]");
    assert_eq!(expand_err(body, ""), ExpandError::NoRuleMatches);
}

#[test]
fn matchers_in_square_and_curly_delimiters() {
    assert_eq!(expand_ok("[$a:ident] => { $a };", "x"), "x");
    assert_eq!(expand_ok("{$a:ident} => { $a };", "x"), "x");
    // Several rules, mixed delimiters: the first that matches wins.
    let body = "[$a:literal] => { 1 }; {$a:ident} => { 2 }; ($a:tt) => { 3 };";
    assert_eq!(expand_ok(body, "5"), "1");
    assert_eq!(expand_ok(body, "n"), "2");
    assert_eq!(expand_ok(body, "+"), "3");
}

#[test]
fn rules_are_tried_in_order() {
    let body = "(a) => { 1 }; ($x:ident) => { 2 }; ($($t:tt)*) => { 3 };";
    assert_eq!(expand_ok(body, "a"), "1");
    assert_eq!(expand_ok(body, "b"), "2");
    assert_eq!(expand_ok(body, "1 2"), "3");
}

#[test]
fn groups_in_the_matcher_match_groups_in_the_input() {
    let body = "(($a:ident, $b:ident) [$c:literal]) => { $a + $b + $c };";
    assert_eq!(expand_ok(body, "(x, y) [3]"), "x+y+3");
    assert_eq!(expand_err(body, "[x, y] (3)"), ExpandError::NoRuleMatches);
    assert_eq!(expand_err(body, "(x, y)"), ExpandError::NoRuleMatches);
}

#[test]
fn muncher_recurses_one_token_per_level() {
    let body = "(@acc [$($acc:tt)*]) => { [$($acc)*] }; \
                (@acc [$($acc:tt)*] $head:tt $($rest:tt)*) => { m!(@acc [$($acc)* $head] $($rest)*) };";
    assert_eq!(expand_ok(body, "@acc [] a b"), "m!(@acc[a]b)");
    assert_eq!(expand_ok(body, "@acc [a b]"), "[ab]");
}

#[test]
fn a_tt_repetition_followed_by_a_token_is_the_ambiguity_rustc_rejects() {
    assert_eq!(
        expand_err("($($t:tt)* ;) => {};", "a ;"),
        ExpandError::Ambiguous
    );
}

// ---------------------------------------------------------------------------
// Transcriber
// ---------------------------------------------------------------------------

#[test]
fn name_colon_type_in_a_transcriber_is_not_a_fragment() {
    let body =
        "($f:ident, $t:ident) => { struct S { $f: u32 } fn g($f: $t) { let $f: u32 = 0; } };";
    assert_eq!(
        expand_ok(body, "field, u8"),
        "structS{field:u32}fng(field:u8){letfield:u32=0;}"
    );
}

#[test]
fn dollar_crate_becomes_the_defining_crate() {
    let body = "($n:ident) => { $crate::helpers::$n() };";
    let def = definition(body);
    let own = expand(&def, "crate", tokens("go"), "1").expect("own crate");
    assert_eq!(squash(&own.tokens), "crate::helpers::go()");
    let other = expand(&def, "other_crate", tokens("go"), "1").expect("other crate");
    assert_eq!(squash(&other.tokens), "other_crate::helpers::go()");
    // A crate name that is not an identifier cannot panic the expander.
    let odd = expand(&def, "not an ident", tokens("go"), "1").expect("odd name");
    assert_eq!(squash(&odd.tokens), "crate::helpers::go()");
}

#[test]
fn repetition_count_mismatch_is_reported_not_guessed() {
    let body = "($($a:ident),* ; $($b:ident),*) => { $( ($a, $b) ),* };";
    assert!(matches!(
        expand_err(body, "x, y ; z"),
        ExpandError::Transcribe(_)
    ));
    assert_eq!(expand_ok(body, "x, y ; z, w"), "(x,z),(y,w)");
}

#[test]
fn repeated_variable_outside_its_repetition_is_an_error() {
    let body = "($($a:ident),*) => { $a };";
    assert!(matches!(
        expand_err(body, "x, y"),
        ExpandError::Transcribe(_)
    ));
}

#[test]
fn no_rule_matching_is_reported_not_guessed() {
    assert_eq!(
        expand_err("(a b) => {};", "a c"),
        ExpandError::NoRuleMatches
    );
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

fn tokens_of(count: usize, token: &str) -> String {
    vec![token; count].join(" ")
}

#[test]
fn exponential_matcher_stops_quickly_with_a_diagnostic() {
    let def = definition("($($($t:tt)+)+ !) => {};");
    let input = tokens_of(40, "a");
    let started = Instant::now();
    let result = expand(&def, "krate", tokens(&input), "1");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(result.err(), Some(ExpandError::Ambiguous));
}

#[test]
fn polynomial_matcher_stops_quickly_with_a_diagnostic() {
    let def = definition("($($a:tt)* $($b:tt)* $($c:tt)* !) => {};");
    let input = tokens_of(400, "a");
    let started = Instant::now();
    let result = expand(&def, "krate", tokens(&input), "1");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(result.err(), Some(ExpandError::Ambiguous));
}

#[test]
fn step_budget_stops_a_match_that_runs_too_long() {
    let def = definition("($($t:tt)*) => { [$($t)*] };");
    let input = tokens_of(5_000, "a");
    // A long, legitimate input fits the budget ...
    assert!(expand(&def, "krate", tokens(&input), "1").is_ok());
    // ... and the same input does not fit a small one.
    let started = Instant::now();
    let result = expand_with_budget(&def, "krate", tokens(&input), "1", 1_000);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(result.err(), Some(ExpandError::StepBudget));
}

#[test]
fn input_that_would_fill_the_default_budget_is_stopped_by_it() {
    // Two optional pieces per iteration keep several threads alive at every
    // token, so the cost grows faster than the input.
    let def = definition("($($a:ident $(, $b:ident)? $(; $c:ident)?)*) => {};");
    let input = tokens_of(300_000, "x");
    let started = Instant::now();
    let result = expand(&def, "krate", tokens(&input), "1");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(matches!(
        result,
        Err(ExpandError::StepBudget | ExpandError::IterationLimit)
    ));
}

#[test]
fn repetition_iteration_cap_is_reported() {
    let def = definition("($($t:tt)*) => { [$($t)*] };");
    let input = tokens_of(MAX_REPETITION_ITERATIONS + 10, "a");
    let result = expand(&def, "krate", tokens(&input), "1");
    assert_eq!(result.err(), Some(ExpandError::IterationLimit));
    let within = tokens_of(MAX_REPETITION_ITERATIONS - 10, "a");
    assert!(expand(&def, "krate", tokens(&within), "1").is_ok());
    // A repetition that runs nearly to its cap costs well under a fifth of the
    // default budget.
    assert!(expand_with_budget(&def, "krate", tokens(&within), "1", MAX_MATCH_STEPS / 5).is_ok());
}

#[test]
fn deeply_nested_input_is_refused_not_overflowed() {
    let def = definition("($($t:tt)*) => { $($t)* };");
    let depth = 1_000;
    let input = format!("{}{}", "(".repeat(depth), ")".repeat(depth));
    let result = expand(&def, "krate", tokens(&input), "1");
    assert_eq!(result.err(), Some(ExpandError::TooDeep));
}

#[test]
fn deeply_nested_definition_is_not_collected() {
    // Deeper source overflows the stack inside `syn::parse_str`, before this
    // module sees it; that limit is not the module's to lift.
    let depth = 1_000;
    let source = format!(
        "macro_rules! deep {{ {}{} => {{}} }}",
        "(".repeat(depth),
        ")".repeat(depth)
    );
    let item: syn::Result<syn::ItemMacro> = syn::parse_str(&source);
    if let Ok(item) = item {
        assert!(scope::parse_rules(&item.mac.tokens).is_none());
    }
}

#[test]
fn malformed_definitions_are_reported() {
    let def = definition("($x) => { $x };");
    assert!(matches!(
        expand(&def, "krate", tokens("a"), "1").err(),
        Some(ExpandError::Malformed(_))
    ));
    let unknown = definition("($x:frobnicate) => { $x };");
    assert!(matches!(
        expand(&unknown, "krate", tokens("a"), "1").err(),
        Some(ExpandError::Malformed(_))
    ));
    let no_operator = definition("($($x:ident)) => { };");
    assert!(matches!(
        expand(&no_operator, "krate", tokens("a"), "1").err(),
        Some(ExpandError::Malformed(_))
    ));
}

// ---------------------------------------------------------------------------
// Input a compiling crate can contain must not panic
// ---------------------------------------------------------------------------

#[test]
fn raw_identifiers_in_a_transcriber_do_not_panic() {
    let body = "($x:ident) => { pub fn $x() { let r#type = 1; let r#match = r#type + 1; \
                println!(\"{r#type}\"); } };";
    let out = expand_ok(body, "a");
    assert!(out.contains("fna()"));
    // The raw binding is renamed to an ordinary identifier, consistently.
    assert!(
        out.contains("letr#type") || out.contains("lettype__rhyg7"),
        "{out}"
    );
    let invalid = "($x:ident) => { let r#self_ = 1; let $x = r#self_; };";
    let _ = expand_ok(invalid, "v");
}

#[test]
fn unusual_tokens_do_not_panic() {
    let bodies = [
        "($x:tt) => { $x $ };",
        "($($x:tt)*) => { $($x)* $$ };",
        "($x:ident) => { let _ = 'a: loop { break 'a; }; };",
        "($x:ident) => { let ($x, ..) = t; };",
        "($x:ident) => { let S { $x, .. } = s; };",
        "($x:ident) => { for r#in in 0..1 { let _ = r#in; } };",
        "($x:ident) => { let f = |r#a, (b, c): (u8, u8)| r#a + b + c; };",
    ];
    for body in bodies {
        let def = definition(body);
        for input in ["a", "+", "r#raw", "'a", "\"s\"", "1", "(", "", "(((", "))"] {
            if let Ok(stream) = input.parse::<TokenStream>() {
                let _ = expand(&def, "krate", stream, "3");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Hygiene
// ---------------------------------------------------------------------------

fn hygienic(body: &str, input: &str) -> String {
    let def = definition(body);
    let expansion = expand(&def, "krate", tokens(input), "3").expect("expands");
    squash(&expansion.tokens)
}

fn stripped(body: &str, input: &str) -> String {
    strip_suffixes(&hygienic(body, input)).to_string()
}

#[test]
fn let_and_let_mut_and_let_ref_bindings_are_renamed_with_their_uses() {
    let out = hygienic(
        "($v:expr) => { let x = 1; let mut y = $v; y += x; x };",
        "z",
    );
    assert!(out.contains("letx__rhyg3=1"), "{out}");
    assert!(out.contains("letmuty__rhyg3=z"), "{out}");
    assert!(out.contains("y__rhyg3+=x__rhyg3"), "{out}");
    let by_ref = hygienic(
        "($v:expr) => { let ref r = $v; let ref mut q = $v; (r, q) };",
        "z",
    );
    assert!(by_ref.contains("letrefr__rhyg3"), "{by_ref}");
    assert!(by_ref.contains("letrefmutq__rhyg3"), "{by_ref}");
    assert!(by_ref.contains("(r__rhyg3,q__rhyg3)"), "{by_ref}");
}

#[test]
fn tuple_and_struct_patterns_are_renamed() {
    let out = hygienic(
        "($v:expr) => { let (a, (b, _)) = $v; let P { f, g: h } = $v; a + b + f + h };",
        "t",
    );
    assert!(out.contains("let(a__rhyg3,(b__rhyg3,_))"), "{out}");
    // A shorthand field keeps the field name and renames the binding.
    assert!(out.contains("letP{f:f__rhyg3,g:h__rhyg3}"), "{out}");
    assert!(out.contains("a__rhyg3+b__rhyg3+f__rhyg3+h__rhyg3"), "{out}");
}

#[test]
fn if_let_while_let_for_closure_and_match_bindings_are_renamed() {
    let out = hygienic(
        "($e:expr) => { \
            if let Some(v) = $e { v } else { 0 }; \
            while let Some(w) = $e { w; } \
            for i in 0..3 { i; } \
            let c = |p, q: u8| p + q; \
            match $e { Some(m) if m > 1 => m, Some(n) => n, None => 0 }; \
        };",
        "o",
    );
    assert!(out.contains("ifletSome(v__rhyg3)"), "{out}");
    assert!(out.contains("{v__rhyg3}"), "{out}");
    assert!(out.contains("whileletSome(w__rhyg3)"), "{out}");
    assert!(out.contains("fori__rhyg3in0..3{i__rhyg3;}"), "{out}");
    assert!(
        out.contains("|p__rhyg3,q__rhyg3:u8|p__rhyg3+q__rhyg3"),
        "{out}"
    );
    assert!(
        out.contains("Some(m__rhyg3)ifm__rhyg3>1=>m__rhyg3"),
        "{out}"
    );
    assert!(out.contains("Some(n__rhyg3)=>n__rhyg3"), "{out}");
    // `Some` and `None` are constructors, never renamed.
    assert!(!out.contains("Some__"), "{out}");
    assert!(!out.contains("None__"), "{out}");
}

#[test]
fn inline_format_arguments_follow_the_renamed_binding() {
    let out = hygienic(
        "($e:expr) => { let x = $e; println!(\"{x} and {x:?} and {{x}}\"); };",
        "1",
    );
    assert!(out.contains("{x__rhyg3}"), "{out}");
    assert!(out.contains("{x__rhyg3:?}"), "{out}");
    assert!(out.contains("{{x}}"), "{out}");
    // A string that is not a macro argument is left alone.
    let plain = hygienic("($e:expr) => { let x = $e; let s = \"{x}\"; };", "1");
    assert!(plain.contains("\"{x}\""), "{plain}");
}

#[test]
fn names_that_are_not_bindings_are_never_renamed() {
    let out = hygienic(
        "($e:expr) => { \
            let parse = dep::parse($e); \
            let s = Point { parse: 1, other: parse }; \
            let n = s.parse; \
            let m = s.parse(); \
            parse!(parse); \
            fn parse() {} \
            parse::go(); \
            self::parse(); \
            let t: parse::Ty = parse; \
        };",
        "1",
    );
    // The binding and its single-segment uses are renamed ...
    assert!(out.contains("letparse__rhyg3=dep::parse("), "{out}");
    assert!(out.contains("other:parse__rhyg3"), "{out}");
    assert!(out.contains("t__rhyg3:parse::Ty=parse__rhyg3"), "{out}");
    // ... the path segment, the struct key, the field, the method, the
    // macro name, the item name and the module path are not.
    assert!(out.contains("dep::parse("), "{out}");
    assert!(out.contains("Point{parse:1"), "{out}");
    assert!(out.contains("=s__rhyg3.parse;"), "{out}");
    assert!(out.contains("=s__rhyg3.parse();"), "{out}");
    assert!(out.contains("parse!(parse__rhyg3)"), "{out}");
    assert!(out.contains("fnparse(){}"), "{out}");
    assert!(out.contains("parse::go()"), "{out}");
    assert!(out.contains("self::parse()"), "{out}");
}

#[test]
fn types_and_metavariable_tokens_keep_their_spelling() {
    let out = hygienic(
        "($x:ident, $v:expr) => { let x = 1; let $x = $v; let y: Vec<x> = vec![x]; };",
        "x, x",
    );
    // The caller's `x` (through `$x` and `$v`) keeps its spelling.
    assert!(out.contains("letx=x;"), "{out}");
    assert!(out.contains("letx__rhyg3=1;"), "{out}");
}

#[test]
fn caller_variable_does_not_alias_a_macro_local() {
    // The macro's own `x` is renamed; the caller's `x` stays `x`.
    let out = hygienic("($v:expr) => { let x = \"safe\"; write(path, $v); };", "x");
    assert!(out.contains("letx__rhyg3=\"safe\""), "{out}");
    assert!(out.contains("write(path,x)"), "{out}");
}

#[test]
fn nested_functions_and_attributes_are_left_alone() {
    let out = hygienic(
        "() => { let a = 1; #[derive(a)] struct S; fn inner(a: u8) -> u8 { let b = a; b } a };",
        "",
    );
    assert!(out.contains("leta__rhyg3=1"), "{out}");
    assert!(out.contains("#[derive(a)]"), "{out}");
    assert!(out.contains("fninner(a:u8)->u8{letb=a;b}"), "{out}");
    assert!(out.ends_with("a__rhyg3"), "{out}");
}

#[test]
fn suffixes_strip_back_to_the_source_names() {
    let body = "($v:expr) => { let x = $v; let mut y = x; y += 1; println!(\"{y}\"); y };";
    let text = stripped(body, "z");
    assert!(!text.contains("__rhyg"), "{text}");
    assert!(text.contains("letx=z"), "{text}");
    assert!(text.contains("{y}"), "{text}");
    assert_eq!(strip_suffixes("plain").as_ref(), "plain");
    assert_eq!(strip_suffixes("a__rhyg12b__rhyg3").as_ref(), "ab");
}

#[test]
fn two_invocations_rename_apart() {
    let def = definition("() => { let x = 1; x };");
    let first = expand(&def, "krate", tokens(""), "1").expect("first");
    let second = expand(&def, "krate", tokens(""), "2").expect("second");
    assert_ne!(squash(&first.tokens), squash(&second.tokens));
}
