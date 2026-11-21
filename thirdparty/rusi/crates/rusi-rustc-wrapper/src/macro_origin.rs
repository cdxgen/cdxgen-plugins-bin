//! Where a span's code comes from, read from rustc's macro expansion data.
//!
//! The wrapper sees the crate after macro expansion, so evidence produced
//! from a macro's transcribed code carries the expansion's hygiene context.
//! That context answers three questions for every span: was the code written
//! by a macro, which crate defines that macro, and where in the workspace's
//! own macros the code sits. Signals raised inside an expansion whose macro
//! is defined outside the workspace belong to that dependency, not to the
//! user's code, so they are not emitted; evidence inside a workspace macro's
//! expansion is kept and names the macro.

use std::path::{Path, PathBuf};

use rusi_schema::{ExpandedFrom, relative_display_path};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_middle::ty::TyCtxt;
use rustc_span::{ExpnData, ExpnKind, FileName, MacroKind, Span};

/// The macro origin of one span, from its expansion backtrace.
#[derive(Clone, Debug, Default)]
pub(crate) struct ExpansionOrigin {
    /// The dependency bang macro the span's code is attributed to, named the
    /// way the stable backend names a macro call: `log::info!`. None when no
    /// dependency macro took part, or only a std one did.
    pub(crate) via_macro: Option<String>,
    /// The outermost workspace macro in the backtrace, when one is there.
    pub(crate) expanded_from: Option<ExpandedFrom>,
    /// The span's code was produced by macro expansions, and every macro in
    /// the backtrace is defined outside the workspace (std, core, alloc or a
    /// dependency). A signal on such a span is the dependency's, not the
    /// user's.
    pub(crate) from_foreign_expansion_only: bool,
}

/// Walks a span's macro expansions, innermost first, as far as rustc
/// recorded them. Desugarings and compiler passes are not macros and are
/// left out: code they generate comes from the user's own line.
fn macro_backtrace(span: Span) -> Vec<ExpnData> {
    span.macro_backtrace()
        .filter(|expn| matches!(expn.kind, ExpnKind::Macro(..)))
        .collect()
}

/// Reads the origin of `span`: which macro wrote its code, and where.
pub(crate) fn expansion_origin(tcx: TyCtxt<'_>, root: &Path, span: Span) -> ExpansionOrigin {
    let backtrace = macro_backtrace(span);
    if backtrace.is_empty() {
        return ExpansionOrigin::default();
    }
    let workspace_positions: Vec<usize> = backtrace
        .iter()
        .enumerate()
        .filter(|(_, expn)| expansion_is_workspace(tcx, root, expn))
        .map(|(position, _)| position)
        .collect();

    // The macro a call is attributed to is the outermost dependency macro of
    // the backtrace: the one the invoking line wrote. Expansions inside it,
    // such as log's `__log!` or serde_json's `json_internal!`, are the
    // dependency's own plumbing, and std macros are not named as calls into
    // a dependency, matching the stable backend's resolution.
    let via_macro = backtrace.iter().rev().find_map(|expn| {
        if let ExpnKind::Macro(MacroKind::Bang, _) = expn.kind
            && let Some(def_id) = expn.macro_def_id
            && !expansion_is_workspace(tcx, root, expn)
            && !is_std_crate(tcx, def_id)
        {
            return Some(format!("{}!", def_path_str_of(tcx, def_id)));
        }
        None
    });

    let expanded_from = workspace_positions
        .last()
        .map(|&outermost| expanded_from_for(tcx, root, span, &backtrace, outermost));
    ExpansionOrigin {
        via_macro,
        expanded_from,
        from_foreign_expansion_only: workspace_positions.is_empty(),
    }
}

/// `expanded_from` for evidence whose outermost workspace macro expansion is
/// `outermost` in the backtrace. The location is the transcriber token the
/// macro wrote the code from: the call site of the expansion nested inside
/// it, or the span itself when the workspace macro's expansion is the
/// innermost one. A token pasted from the invocation arguments sits at the
/// call site rather than in the transcriber, so its file is compared with
/// the definition's file, and the definition is reported when they differ.
fn expanded_from_for(
    tcx: TyCtxt<'_>,
    root: &Path,
    span: Span,
    backtrace: &[ExpnData],
    outermost: usize,
) -> ExpandedFrom {
    let expn = &backtrace[outermost];
    let macro_path = expn
        .macro_def_id
        .map(|def_id| def_path_str_of(tcx, def_id))
        .unwrap_or_default();
    let (file_path, line) = origin_location(tcx, root, span, backtrace, outermost);
    ExpandedFrom {
        macro_path,
        file_path,
        line,
    }
}

/// The file and line the `outermost` workspace expansion's transcriber sits
/// at, or of its definition when no transcriber token is local.
fn origin_location(
    tcx: TyCtxt<'_>,
    root: &Path,
    span: Span,
    backtrace: &[ExpnData],
    outermost: usize,
) -> (String, usize) {
    let definition_span = definition_span_of(tcx, &backtrace[outermost]);
    let definition_file = file_display_path(tcx, root, definition_span);
    // The token the workspace macro transcribed that led here: the span
    // itself when its expansion is this one, otherwise the invocation of the
    // inner expansion, which is a token of this expansion's output.
    let candidate = if outermost == 0 {
        span
    } else {
        backtrace[outermost - 1].call_site
    };
    if let Some(path) = candidate_file_path(tcx, candidate) {
        let display = relative_display_path(root, &path);
        // A token pasted from the invocation arguments sits in the invoking
        // file, not in the definition's file; the definition is reported for
        // it instead of a line the macro never wrote.
        if Some(&display) == definition_file.as_ref()
            && let Some(line) = line_at(tcx, candidate)
        {
            return (display, line);
        }
    }
    let fallback = definition_file.unwrap_or_else(|| "<non-local>".to_string());
    let line = line_at(tcx, definition_span).unwrap_or(0);
    (fallback, line)
}

/// The span rustc records as the macro's definition, or the definition item's
/// span when the expansion data carries none.
fn definition_span_of(tcx: TyCtxt<'_>, expn: &ExpnData) -> Span {
    if let Some(def_id) = expn.macro_def_id {
        return tcx.def_span(def_id);
    }
    expn.call_site
}

fn expansion_is_workspace(tcx: TyCtxt<'_>, root: &Path, expn: &ExpnData) -> bool {
    let Some(def_id) = expn.macro_def_id else {
        return false;
    };
    def_id.krate == LOCAL_CRATE || macro_defined_under_root(tcx, root, def_id)
}

/// Whether the macro is one of the standard library's. The stable backend
/// resolves `std`, `core` and `alloc` to their own target rather than to a
/// dependency, so a call into them is not a dependency macro call either.
fn is_std_crate(tcx: TyCtxt<'_>, def_id: DefId) -> bool {
    matches!(
        tcx.crate_name(def_id.krate).as_str(),
        "std" | "core" | "alloc"
    )
}

/// Whether a foreign macro is defined by another crate of the analysed
/// workspace: its definition file sits under the analysis root. Sources of
/// std, core, alloc and of registry dependencies sit elsewhere.
fn macro_defined_under_root(tcx: TyCtxt<'_>, root: &Path, def_id: DefId) -> bool {
    let Some(span) = tcx.def_ident_span(def_id) else {
        return false;
    };
    let Some(path) = candidate_file_path(tcx, span) else {
        return false;
    };
    path_is_under_root(root, &path)
}

/// rustc's path of a macro, named the way the report names macros:
/// `log::info` for a dependency, and the defining crate's name for the local
/// one, so a workspace macro's path matches the `kind: "macro"` declaration
/// the stable backend declares for it.
fn def_path_str_of(tcx: TyCtxt<'_>, def_id: DefId) -> String {
    let path = tcx.def_path_str(def_id);
    if def_id.krate == LOCAL_CRATE {
        let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
        return format!("{crate_name}::{path}");
    }
    path
}

/// The real path of the file a span's start sits in, when rustc has that
/// file on its source map and the path is a local one.
fn candidate_file_path(tcx: TyCtxt<'_>, span: Span) -> Option<PathBuf> {
    let file = tcx.sess.source_map().lookup_char_pos(span.lo()).file;
    match &file.name {
        FileName::Real(real) => real.clone().into_local_path(),
        _ => None,
    }
}

fn line_at(tcx: TyCtxt<'_>, span: Span) -> Option<usize> {
    Some(tcx.sess.source_map().lookup_char_pos(span.lo()).line)
}

/// The path as the report names it: relative to the analysis root, falling
/// back to the full path for a file outside it.
fn file_display_path(tcx: TyCtxt<'_>, root: &Path, span: Span) -> Option<String> {
    candidate_file_path(tcx, span).map(|path| relative_display_path(root, &path))
}

fn canonical_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn path_is_under_root(root: &Path, path: &Path) -> bool {
    canonical_path(path).starts_with(canonical_path(root))
}
