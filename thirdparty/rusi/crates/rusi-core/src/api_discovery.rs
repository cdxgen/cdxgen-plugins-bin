//! API endpoint discovery pass.
//!
//! Recognises HTTP framework router-building patterns in parsed Rust
//! source and lifts them into structured [`ApiEndpoint`] entries on the
//! report. The existing per-file collector captures method calls but drops
//! literal values; this pass re-parses each file with `syn` and walks the
//! AST directly so it can preserve the path strings and handler names that
//! the router DSL relies on.
//!
//! ## Supported frameworks
//!
//! - **axum** — `Router::new().route(PATH, METHOD(HANDLER))`, method
//!   chaining (`get(h).post(h2)`), and `.nest(PREFIX, SUB)` composition
//!   where `SUB` is a call to a router-building function or a local
//!   binding that itself holds a `Router::new()...` chain.
//! - **actix-web** — `App::new().service(...)`, `web::resource(PATH)`,
//!   `web::scope(PREFIX).service(...)`, and route attribute macros
//!   (`#[get("/path")]`, `#[post("/path")]`, etc.) plus the
//!   `App::new().service(handler)` registration of attribute-macro
//!   handlers.
//! - **rocket** — route attribute macros (`#[get("/path")]`,
//!   `#[post("/path", ...)]`, etc.) plus mounting through
//!   `rocket::build().mount(BASE, routes![h1, h2, ...])`.
//!
//! Warp is intentionally deferred: its filter-combinator style requires
//! fundamentally different analysis and will land in a follow-up.
//!
//! ## Handler signature extraction
//!
//! Once endpoints are resolved, each handler is looked up in the captured
//! function declarations and its signature is parsed to extract:
//!
//! - Path parameters (axum `Path<T>` extractor, actix `web::Path<T>`,
//!   rocket bare-name parameters whose name appears in the route path).
//! - Query parameters (axum `Query<T>`, actix `web::Query<T>`,
//!   rocket `Form<T>`-style query bindings).
//! - Request body type (axum `Json<T>`, actix `web::Json<T>`,
//!   rocket `Json<T>` / `Form<T>`).
//! - Response type (the inner type of `Result<Json<U>, _>` and similar
//!   shapes, or the plain return type).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;

use indexmap::IndexMap;
use quote::ToTokens;
use rusi_schema::{ApiEndpoint, EndpointParameter, ImportUsage, Position};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{
    Attribute, Expr, ExprCall, ExprLit, ExprMacro, ExprMethodCall, ExprPath, FnArg, GenericArgument,
    Item, ItemFn, ItemUse, Lit, Local, Macro, PatType, PathArguments, ReturnType, Stmt, Type,
    UseTree,
};

use crate::{PackageContext, position_from_span, relative_display_path, stable_id};

pub(crate) const FRAMEWORK_AXUM: &str = "axum";
pub(crate) const FRAMEWORK_ACTIX: &str = "actix-web";
pub(crate) const FRAMEWORK_ROCKET: &str = "rocket";

const HTTP_METHOD_NAMES: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
];

/// Per-function-or-local router-builder record. Each entry represents the
/// fragments contributed by a single chain of `.route()`/`.nest()` (axum)
/// or `.service()`/`.scope()` (actix) or `.mount(...)` (rocket) method
/// calls; nesting is resolved later by following references in `Nest`
/// fragments.
#[derive(Debug, Clone)]
struct RouterBuilder {
    /// Key used by `Nest` fragments to refer to this builder. For
    /// functions this is the function's qualified name; for local bindings
    /// it is `qualified_fn_name::local_name`. For attribute-macro
    /// handlers (rocket/actix), the builder key is the handler's
    /// qualified name itself.
    key: String,
    file_path: String,
    package_path: String,
    framework: String,
    fragments: Vec<RouteFragment>,
}

#[derive(Debug, Clone)]
enum RouteFragment {
    Route {
        method: String,
        path: String,
        /// Last segment of the handler's path as written at the call
        /// site. Resolved to a qualified declaration later.
        handler: String,
        position: Position,
    },
    Nest {
        prefix: String,
        /// Reference to another `RouterBuilder.key` (a function name like
        /// `crate::routes::user_routes` or a local-binding key).
        sub_builder: String,
        /// Retained for future diagnostics on unresolved nest targets.
        #[allow(dead_code)]
        position: Position,
    },
}

/// Captured handler-function signature, indexed by qualified name. Used
/// during endpoint resolution to populate the request/response shape.
#[derive(Debug, Clone)]
struct CapturedFunction {
    qualified_name: String,
    file_path: String,
    parameters: Vec<CapturedParameter>,
    return_type: Option<String>,
}

#[derive(Debug, Clone)]
struct CapturedParameter {
    pattern_text: String,
    type_text: String,
}

/// Public entry point. Returns the fully resolved endpoint list for the
/// workspace.
pub(crate) fn discover_api_endpoints(
    package_contexts: &[PackageContext],
    analysis_root: &Path,
    imports: &[ImportUsage],
) -> Vec<ApiEndpoint> {
    let frameworks = detect_frameworks(imports);
    if frameworks.is_empty() {
        return Vec::new();
    }

    let mut builders: BTreeMap<String, RouterBuilder> = BTreeMap::new();
    let mut functions: BTreeMap<String, CapturedFunction> = BTreeMap::new();

    for package_ctx in package_contexts {
        let files = match crate::discover_rust_files(package_ctx, false) {
            Ok(files) => files,
            Err(_) => continue,
        };
        for file_path in files {
            let relative = relative_display_path(analysis_root, &file_path);
            let module_segments = crate::module_path_for_file(package_ctx, &file_path);
            let source = match fs::read_to_string(&file_path) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let syntax = match syn::parse_file(&source) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let file_attr_framework = detect_file_attribute_framework(&syntax);
            let mut collector = BuilderCollector::new(
                package_ctx.crate_name.clone(),
                module_segments,
                relative,
                frameworks.clone(),
                file_attr_framework,
            );
            collector.visit_file(&syntax);
            for builder in collector.builders {
                builders.insert(builder.key.clone(), builder);
            }
            for function in collector.functions {
                functions.insert(function.qualified_name.clone(), function);
            }
        }
    }

    resolve_endpoints(&builders, &functions)
}

fn detect_frameworks(imports: &[ImportUsage]) -> BTreeSet<String> {
    let mut frameworks = BTreeSet::new();
    for import in imports {
        let path = &import.path;
        if path == "axum" || path.starts_with("axum::") {
            frameworks.insert(FRAMEWORK_AXUM.to_string());
        } else if path == "actix_web" || path.starts_with("actix_web::") {
            frameworks.insert(FRAMEWORK_ACTIX.to_string());
        } else if path == "rocket" || path.starts_with("rocket::") {
            frameworks.insert(FRAMEWORK_ROCKET.to_string());
        }
    }
    frameworks
}

/// Visits a single parsed file, collecting router-builder fragments and
/// every function declaration's signature (used later for handler
/// signature extraction).
struct BuilderCollector {
    package_path: String,
    module_segments: Vec<String>,
    file_path: String,
    /// Subset of [`detect_frameworks`] outputs that we've found imported
    /// in the workspace. Used to gate framework-specific extraction so we
    /// don't, for instance, treat an actix `web::scope` as an axum nest.
    frameworks: BTreeSet<String>,
    /// Framework that owns this file's attribute macros, if any. Derived
    /// from per-file `use` statements (see
    /// [`detect_file_attribute_framework`]). Disambiguates which
    /// framework a `#[get(...)]` attribute belongs to when more than one
    /// framework is present in the workspace.
    file_attr_framework: Option<String>,
    builders: Vec<RouterBuilder>,
    functions: Vec<CapturedFunction>,
    current_fn_qualified: Option<String>,
}

impl BuilderCollector {
    fn new(
        package_path: String,
        module_segments: Vec<String>,
        file_path: String,
        frameworks: BTreeSet<String>,
        file_attr_framework: Option<String>,
    ) -> Self {
        Self {
            package_path,
            module_segments,
            file_path,
            frameworks,
            file_attr_framework,
            builders: Vec::new(),
            functions: Vec::new(),
            current_fn_qualified: None,
        }
    }

    fn qualify(&self, name: &str) -> String {
        let mut segments = vec![self.package_path.clone()];
        segments.extend(self.module_segments.iter().cloned());
        segments.push(name.to_string());
        segments.join("::")
    }

    fn record_chain(&mut self, key: String, framework: String, fragments: Vec<RouteFragment>) {
        if fragments.is_empty() {
            return;
        }
        self.builders.push(RouterBuilder {
            key,
            file_path: self.file_path.clone(),
            package_path: self.package_path.clone(),
            framework,
            fragments,
        });
    }
}

impl<'ast> Visit<'ast> for BuilderCollector {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let fn_qualified = self.qualify(&node.sig.ident.to_string());
        let previous = self.current_fn_qualified.replace(fn_qualified.clone());

        // 1. Capture this function's signature for later handler lookup.
        self.functions
            .push(capture_function(&fn_qualified, &self.file_path, &node.sig));

        // 2. Attribute-macro routes (rocket / actix): a single function
        //    annotated with `#[get("/path")]` etc. registers itself. The
        //    framework is determined by the file's own `use` statements
        //    (see [`detect_file_attribute_framework`]) so we don't
        //    misattribute a rocket handler to actix or vice versa when
        //    both crates appear in the workspace.
        if let Some(attr_framework) = self.file_attr_framework.as_ref() {
            let fragments = attribute_macro_route_fragments(&node.attrs, &self.file_path);
            // Attribute-macro handlers register under the handler's own
            // qualified name. A `.mount("/api", routes![my_handler])` or
            // `App::new().service(my_handler)` later refers to them.
            self.record_chain(fn_qualified.clone(), attr_framework.clone(), fragments);
        }

        // 3. Body-level builder chains. axum and actix both use method
        //    chains; we inspect every expression statement plus local
        //    bindings for chains rooted at the appropriate constructor.
        for stmt in &node.block.stmts {
            if let Stmt::Expr(expr, _) = stmt {
                self.collect_body_chains(expr, fn_qualified.clone());
            }
        }
        for stmt in &node.block.stmts {
            if let Stmt::Local(Local {
                pat,
                init: Some(init),
                ..
            }) = stmt
                && let syn::Pat::Ident(pat_ident) = pat
            {
                let local_key = format!("{}::{}", fn_qualified, pat_ident.ident);
                self.collect_body_chains(&init.expr, local_key);
            }
        }

        syn::visit::visit_item_fn(self, node);
        self.current_fn_qualified = previous;
    }
}

impl BuilderCollector {
    /// Collect router-building fragments from an expression, attributing
    /// them to `key`. Dispatches per framework based on the chain root.
    fn collect_body_chains(&mut self, expr: &Expr, key: String) {
        if self.frameworks.contains(FRAMEWORK_AXUM) && chain_root_matches(expr, "Router::new") {
            let mut fragments = Vec::new();
            walk_axum_chain(expr, &mut fragments, &self.file_path);
            self.record_chain(key.clone(), FRAMEWORK_AXUM.to_string(), fragments);
        } else if self.frameworks.contains(FRAMEWORK_ACTIX)
            && (chain_root_matches(expr, "App::new")
                || chain_root_matches_call(expr, "web::scope"))
        {
            let mut fragments = Vec::new();
            walk_actix_chain(expr, &mut fragments, &self.file_path);
            self.record_chain(key.clone(), FRAMEWORK_ACTIX.to_string(), fragments);
        } else if self.frameworks.contains(FRAMEWORK_ROCKET)
            && chain_root_matches(expr, "rocket::build")
        {
            let mut fragments = Vec::new();
            walk_rocket_chain(expr, &mut fragments, &self.file_path);
            self.record_chain(key, FRAMEWORK_ROCKET.to_string(), fragments);
        } else {
            // Recurse into nested expressions to catch chains buried
            // inside other calls (e.g. `axum::serve(listener, app)`).
            match expr {
                Expr::Call(ExprCall { args, .. }) => {
                    for (idx, arg) in args.iter().enumerate() {
                        let sub_key = format!("{}::__arg{}", key, idx);
                        self.collect_body_chains(arg, sub_key);
                    }
                }
                Expr::MethodCall(ExprMethodCall { receiver, args, .. }) => {
                    self.collect_body_chains(receiver, format!("{}::__recv", key));
                    for (idx, arg) in args.iter().enumerate() {
                        let sub_key = format!("{}::__arg{}", key, idx);
                        self.collect_body_chains(arg, sub_key);
                    }
                }
                _ => {}
            }
        }
    }
}

// ─── axum chain extraction ──────────────────────────────────────────────

/// Walk an axum chain rooted at `Router::new()`, emitting one fragment
/// per `.route(...)` and `.nest(...)` call encountered.
fn walk_axum_chain(expr: &Expr, out: &mut Vec<RouteFragment>, file_path: &str) {
    if let Expr::MethodCall(method) = expr {
        walk_axum_chain(&method.receiver, out, file_path);
        let position = position_from_span(file_path, method.span());
        match method.method.to_string().as_str() {
            "route" => extract_axum_route(&method.args, out, position),
            "nest" => {
                if let Some(fragment) = extract_nest_fragment(&method.args, position) {
                    out.push(fragment);
                }
            }
            _ => {}
        }
    }
}

/// Pull `(path_literal, handler_expr)` out of a `.route(PATH, HANDLER)`
/// call. HANDLER is typically `get(handler_fn)` or a chained
/// `get(h).post(h2).delete(h3)`; emit one fragment per method.
fn extract_axum_route(
    args: &syn::punctuated::Punctuated<Expr, syn::Token![,]>,
    out: &mut Vec<RouteFragment>,
    position: Position,
) {
    let Some(path) = args.iter().next().and_then(string_literal_value) else {
        return;
    };
    let Some(handler_expr) = args.iter().nth(1) else {
        return;
    };
    walk_method_router_expr(handler_expr, &path, out, &position);
}

/// Walks a handler-side expression like `get(handler).post(other)` and
/// emits one Route fragment per HTTP method encountered.
fn walk_method_router_expr(
    expr: &Expr,
    path: &str,
    out: &mut Vec<RouteFragment>,
    position: &Position,
) {
    match expr {
        Expr::Call(call) => {
            let callee = callee_last_segment(&call.func);
            if HTTP_METHOD_NAMES.contains(&callee.as_str())
                && let Some(handler) = call.args.iter().next().and_then(path_expr_to_string)
            {
                out.push(RouteFragment::Route {
                    method: callee.to_ascii_uppercase(),
                    path: path.to_string(),
                    handler,
                    position: position.clone(),
                });
            }
        }
        Expr::MethodCall(method) => {
            walk_method_router_expr(&method.receiver, path, out, position);
            let method_name = method.method.to_string();
            if HTTP_METHOD_NAMES.contains(&method_name.as_str())
                && let Some(handler) = method.args.iter().next().and_then(path_expr_to_string)
            {
                out.push(RouteFragment::Route {
                    method: method_name.to_ascii_uppercase(),
                    path: path.to_string(),
                    handler,
                    position: position.clone(),
                });
            }
        }
        _ => {}
    }
}

// ─── actix-web chain extraction ─────────────────────────────────────────

/// Walk an actix chain rooted at `App::new()` or `web::scope("/x")`,
/// emitting fragments for each `.service(...)` call. The argument to
/// `.service()` can be:
///   * a handler reference (`my_attribute_macro_handler`) — registers an
///     attribute-macro handler;
///   * `web::resource(PATH).route(web::get().to(handler))` — explicit
///     resource registration;
///   * `web::scope(PREFIX).service(...)` — nested scope.
fn walk_actix_chain(expr: &Expr, out: &mut Vec<RouteFragment>, file_path: &str) {
    if let Expr::MethodCall(method) = expr {
        walk_actix_chain(&method.receiver, out, file_path);
        let position = position_from_span(file_path, method.span());
        match method.method.to_string().as_str() {
            "service" => extract_actix_service(&method.args, out, position),
            // App::new().route(PATH, web::get().to(handler))
            "route" => extract_actix_route_call(&method.args, out, position),
            _ => {}
        }
    } else if let Expr::Call(call) = expr {
        // web::scope("/api/v1") at the very root — recurse no further;
        // routes inside this scope will be visited when the receiver of
        // a subsequent `.service` is this expression. Handled by the
        // outer dispatch.
        let _ = call;
    }
}

fn extract_actix_service(
    args: &syn::punctuated::Punctuated<Expr, syn::Token![,]>,
    out: &mut Vec<RouteFragment>,
    position: Position,
) {
    let Some(arg) = args.iter().next() else {
        return;
    };
    match arg {
        // .service(handler_with_attribute_macro)
        Expr::Path(path_expr) => {
            if let Some(handler) = path_expr_to_string(arg) {
                out.push(RouteFragment::Nest {
                    prefix: String::new(),
                    sub_builder: last_path_segment(path_expr).unwrap_or(handler),
                    position,
                });
            }
        }
        // .service(web::resource("/users").route(web::get().to(list_users)))
        Expr::MethodCall(_) | Expr::Call(_) => {
            extract_actix_service_expr(arg, "", out, &position);
        }
        _ => {}
    }
}

/// Walks a `.service(EXPR)` argument that may itself be a chain like
/// `web::scope("/api/v1").service(...)` or
/// `web::resource("/users").route(...)`.
fn extract_actix_service_expr(
    expr: &Expr,
    prefix: &str,
    out: &mut Vec<RouteFragment>,
    position: &Position,
) {
    match expr {
        Expr::Call(call) => {
            let callee = call.func.to_token_stream().to_string().replace(' ', "");
            if callee == "web::resource" || callee.ends_with("::web::resource") {
                if let Some(path) = call.args.iter().next().and_then(string_literal_value) {
                    let full_path = join_prefix(prefix, &path);
                    out.push(RouteFragment::Route {
                        method: "GET".to_string(),
                        path: full_path,
                        handler: String::new(),
                        position: position.clone(),
                    });
                    // The actual method/handler come from `.route(...)`
                    // chained onto this resource — handled in the
                    // MethodCall branch below; emit a placeholder above
                    // gets replaced when we see route calls on the
                    // resource. We don't emit it directly; remove placeholder.
                    out.pop();
                }
            } else if callee == "web::scope" || callee.ends_with("::web::scope") {
                if let Some(scope_prefix) = call.args.iter().next().and_then(string_literal_value)
                {
                    let _ = join_prefix(prefix, &scope_prefix);
                    // Scope alone contributes no routes; routes only
                    // appear when chained with `.service(...)`.
                }
            }
        }
        Expr::MethodCall(method) => {
            // Descend the receiver to discover the scope/resource it was
            // chained off, then handle this call.
            let (chain_kind, chain_prefix) = inspect_actix_chain_root(&method.receiver);
            let effective_prefix = match chain_prefix.as_ref() {
                Some(p) => join_prefix(prefix, p),
                None => prefix.to_string(),
            };

            let method_name = method.method.to_string();
            match method_name.as_str() {
                "route" => {
                    if matches!(chain_kind, ActixChainRoot::Resource)
                        && let Some(resource_path) = chain_prefix.as_ref()
                        && let Some(method_to_call) = method.args.iter().next()
                        && let Some((http_method, handler)) =
                            extract_actix_route_method_handler(method_to_call)
                    {
                        out.push(RouteFragment::Route {
                            method: http_method,
                            path: join_prefix(prefix, resource_path),
                            handler,
                            position: position.clone(),
                        });
                    }
                }
                "service" => {
                    // Could be a scope().service(further_chain) or
                    // scope().service(handler_fn).
                    if let Some(svc_arg) = method.args.iter().next() {
                        extract_actix_service_expr(svc_arg, &effective_prefix, out, position);
                    }
                }
                _ => {}
            }
            // Continue walking the receiver for further chained calls.
            extract_actix_service_expr(&method.receiver, prefix, out, position);
        }
        _ => {}
    }
}

/// Classification of an actix chain's root. The path literal that
/// `web::scope`/`web::resource` was constructed with is returned
/// separately by [`inspect_actix_chain_root`].
enum ActixChainRoot {
    Scope,
    Resource,
    Other,
}

/// Returns the chain-root classification plus, when applicable, the path
/// literal it was constructed with.
fn inspect_actix_chain_root(expr: &Expr) -> (ActixChainRoot, Option<String>) {
    match expr {
        Expr::Call(call) => {
            let callee = call.func.to_token_stream().to_string().replace(' ', "");
            if callee == "web::scope" || callee.ends_with("::web::scope") {
                let prefix = call.args.iter().next().and_then(string_literal_value);
                (ActixChainRoot::Scope, prefix)
            } else if callee == "web::resource" || callee.ends_with("::web::resource") {
                let path = call.args.iter().next().and_then(string_literal_value);
                (ActixChainRoot::Resource, path)
            } else {
                (ActixChainRoot::Other, None)
            }
        }
        Expr::MethodCall(method) => inspect_actix_chain_root(&method.receiver),
        _ => (ActixChainRoot::Other, None),
    }
}

/// Pull `(HTTP_METHOD, handler)` out of `web::get().to(handler)` or
/// `web::post().to(handler)`.
fn extract_actix_route_method_handler(expr: &Expr) -> Option<(String, String)> {
    if let Expr::MethodCall(method) = expr
        && method.method == "to"
    {
        let http_method = match &*method.receiver {
            Expr::Call(call) => {
                let callee = call.func.to_token_stream().to_string().replace(' ', "");
                let last = callee.rsplit("::").next().unwrap_or("");
                if HTTP_METHOD_NAMES.contains(&last) {
                    last.to_ascii_uppercase()
                } else {
                    return None;
                }
            }
            _ => return None,
        };
        let handler = method.args.iter().next().and_then(path_expr_to_string)?;
        return Some((http_method, handler));
    }
    None
}

/// `App::new().route(PATH, web::get().to(handler))` — actix's explicit
/// per-route registration without going through `web::resource`.
fn extract_actix_route_call(
    args: &syn::punctuated::Punctuated<Expr, syn::Token![,]>,
    out: &mut Vec<RouteFragment>,
    position: Position,
) {
    let Some(path) = args.iter().next().and_then(string_literal_value) else {
        return;
    };
    let Some(method_to_call) = args.iter().nth(1) else {
        return;
    };
    if let Some((http_method, handler)) = extract_actix_route_method_handler(method_to_call) {
        out.push(RouteFragment::Route {
            method: http_method,
            path,
            handler,
            position,
        });
    }
}

// ─── rocket chain extraction ────────────────────────────────────────────

/// Walk a rocket chain rooted at `rocket::build()`, looking for
/// `.mount(BASE, routes![h1, h2, ...])` calls. Each handler named in
/// `routes![]` becomes a Nest fragment whose sub_builder is the handler's
/// last-segment name; the matching attribute-macro builders are joined
/// to produce the final endpoints.
fn walk_rocket_chain(expr: &Expr, out: &mut Vec<RouteFragment>, file_path: &str) {
    if let Expr::MethodCall(method) = expr {
        walk_rocket_chain(&method.receiver, out, file_path);
        if method.method == "mount" {
            let position = position_from_span(file_path, method.span());
            let Some(base) = method.args.iter().next().and_then(string_literal_value) else {
                return;
            };
            if let Some(Expr::Macro(ExprMacro { mac, .. })) = method.args.iter().nth(1) {
                let handlers = parse_routes_macro_handlers(mac);
                for handler in handlers {
                    out.push(RouteFragment::Nest {
                        prefix: base.clone(),
                        sub_builder: handler,
                        position: position.clone(),
                    });
                }
            }
        }
    }
}

/// `routes![h1, m::h2, ::path::h3]` — parse the tokens between brackets
/// into a list of handler last-segment names.
fn parse_routes_macro_handlers(mac: &Macro) -> Vec<String> {
    let tokens_text = mac.tokens.to_string();
    let mut handlers = Vec::new();
    for entry in tokens_text.split(',') {
        let cleaned = entry.trim().trim_start_matches("::");
        if cleaned.is_empty() {
            continue;
        }
        let last = cleaned.rsplit("::").next().unwrap_or(cleaned).trim();
        if !last.is_empty() {
            handlers.push(last.to_string());
        }
    }
    handlers
}

// ─── attribute-macro routes (rocket / actix) ────────────────────────────

/// Inspect `#[get("/path")]` style attributes on a function. Returns one
/// fragment per matching attribute; the caller assigns the framework
/// based on the file's `use` statements.
fn attribute_macro_route_fragments(attrs: &[Attribute], file_path: &str) -> Vec<RouteFragment> {
    let mut out = Vec::new();
    for attr in attrs {
        let Some(path_text) = attribute_method_path(attr) else {
            continue;
        };
        if !HTTP_METHOD_NAMES.contains(&path_text.as_str()) {
            continue;
        }
        let Some(path_literal) = first_string_in_attribute(attr) else {
            continue;
        };
        let position = position_from_span(file_path, attr.span());
        out.push(RouteFragment::Route {
            method: path_text.to_ascii_uppercase(),
            path: path_literal,
            handler: String::new(), // handler == enclosing function (set by record)
            position,
        });
    }
    out
}

/// Inspect a file's `use` statements to decide which framework owns its
/// bare `#[get]`/`#[post]`-style attribute macros. Returns the first
/// framework detected; if a file imports both rocket and actix, the one
/// imported first wins (which mirrors real-world precedence as
/// developers virtually always isolate framework code per module).
fn detect_file_attribute_framework(syntax: &syn::File) -> Option<String> {
    for item in &syntax.items {
        if let Item::Use(ItemUse { tree, .. }) = item
            && let Some(framework) = framework_owning_macro_use(tree)
        {
            return Some(framework);
        }
    }
    None
}

/// Walk a `use` tree looking for an import that pulls in an HTTP method
/// macro (`get`, `post`, `put`, ...) or a glob from a known framework
/// crate. Returns the framework name when found.
fn framework_owning_macro_use(tree: &UseTree) -> Option<String> {
    walk_use_tree(tree, &[])
}

fn walk_use_tree(tree: &UseTree, prefix: &[String]) -> Option<String> {
    match tree {
        UseTree::Path(use_path) => {
            let mut extended = prefix.to_vec();
            extended.push(use_path.ident.to_string());
            walk_use_tree(&use_path.tree, &extended)
        }
        UseTree::Group(group) => {
            for item in &group.items {
                if let Some(found) = walk_use_tree(item, prefix) {
                    return Some(found);
                }
            }
            None
        }
        UseTree::Glob(_) => {
            // `use rocket::*` or `use actix_web::*` — accept as evidence
            // that this file uses that framework's macros.
            classify_framework_from_segments(prefix)
        }
        UseTree::Name(name) => {
            let leaf = name.ident.to_string();
            if HTTP_METHOD_NAMES.contains(&leaf.as_str()) {
                classify_framework_from_segments(prefix)
            } else {
                None
            }
        }
        UseTree::Rename(rename) => {
            let leaf = rename.ident.to_string();
            if HTTP_METHOD_NAMES.contains(&leaf.as_str()) {
                classify_framework_from_segments(prefix)
            } else {
                None
            }
        }
    }
}

fn classify_framework_from_segments(segments: &[String]) -> Option<String> {
    let first = segments.first()?;
    match first.as_str() {
        "rocket" => Some(FRAMEWORK_ROCKET.to_string()),
        "actix_web" => Some(FRAMEWORK_ACTIX.to_string()),
        _ => None,
    }
}

/// `#[get("/path")]` → returns `Some("get")`; non-route attributes
/// return None.
fn attribute_method_path(attr: &Attribute) -> Option<String> {
    let path = attr.path();
    let last = path.segments.last()?;
    let name = last.ident.to_string();
    if HTTP_METHOD_NAMES.contains(&name.as_str()) {
        Some(name)
    } else {
        None
    }
}

fn first_string_in_attribute(attr: &Attribute) -> Option<String> {
    let tokens = attr.meta.to_token_stream().to_string();
    // Look for the first quoted string literal in the attribute tokens.
    let mut chars = tokens.chars().peekable();
    let mut in_string = false;
    let mut collected = String::new();
    while let Some(ch) = chars.next() {
        if !in_string && ch == '"' {
            in_string = true;
            continue;
        }
        if in_string {
            if ch == '\\' {
                if let Some(next) = chars.next() {
                    collected.push(next);
                }
                continue;
            }
            if ch == '"' {
                return Some(collected);
            }
            collected.push(ch);
        }
    }
    None
}

// ─── nest extraction (shared by axum and rocket-via-mount) ──────────────

fn extract_nest_fragment(
    args: &syn::punctuated::Punctuated<Expr, syn::Token![,]>,
    position: Position,
) -> Option<RouteFragment> {
    let prefix = args.iter().next().and_then(string_literal_value)?;
    let sub_expr = args.iter().nth(1)?;
    let sub_builder = match sub_expr {
        Expr::Call(call) => callee_last_segment(&call.func),
        Expr::Path(path_expr) => path_expr
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())?,
        _ => return None,
    };
    Some(RouteFragment::Nest {
        prefix,
        sub_builder,
        position,
    })
}

// ─── small helpers shared across frameworks ─────────────────────────────

fn chain_root_matches(expr: &Expr, target: &str) -> bool {
    match expr {
        Expr::MethodCall(method) => chain_root_matches(&method.receiver, target),
        Expr::Call(call) => {
            let callee = call.func.to_token_stream().to_string().replace(' ', "");
            callee == target || callee.ends_with(&format!("::{}", target))
        }
        _ => false,
    }
}

fn chain_root_matches_call(expr: &Expr, target: &str) -> bool {
    if let Expr::Call(call) = expr {
        let callee = call.func.to_token_stream().to_string().replace(' ', "");
        callee == target || callee.ends_with(&format!("::{}", target))
    } else if let Expr::MethodCall(method) = expr {
        chain_root_matches_call(&method.receiver, target)
    } else {
        false
    }
}

fn string_literal_value(expr: &Expr) -> Option<String> {
    if let Expr::Lit(ExprLit {
        lit: Lit::Str(lit_str),
        ..
    }) = expr
    {
        Some(lit_str.value())
    } else {
        None
    }
}

fn path_expr_to_string(expr: &Expr) -> Option<String> {
    if let Expr::Path(ExprPath { path, .. }) = expr {
        Some(
            path.segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>()
                .join("::"),
        )
    } else {
        None
    }
}

fn last_path_segment(path_expr: &ExprPath) -> Option<String> {
    path_expr
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn callee_last_segment(expr: &Expr) -> String {
    if let Expr::Path(ExprPath { path, .. }) = expr
        && let Some(segment) = path.segments.last()
    {
        return segment.ident.to_string();
    }
    expr.to_token_stream().to_string()
}

fn join_prefix(prefix: &str, child: &str) -> String {
    let prefix = prefix.trim_end_matches('/');
    if child.is_empty() {
        return prefix.to_string();
    }
    if child == "/" {
        if prefix.is_empty() {
            "/".to_string()
        } else {
            prefix.to_string()
        }
    } else if child.starts_with('/') {
        format!("{}{}", prefix, child)
    } else if prefix.is_empty() {
        format!("/{}", child)
    } else {
        format!("{}/{}", prefix, child)
    }
}

// ─── handler signature capture and parameter extraction ─────────────────

fn capture_function(
    qualified_name: &str,
    file_path: &str,
    sig: &syn::Signature,
) -> CapturedFunction {
    let mut parameters = Vec::new();
    for input in &sig.inputs {
        if let FnArg::Typed(PatType { pat, ty, .. }) = input {
            parameters.push(CapturedParameter {
                pattern_text: pat.to_token_stream().to_string().replace(' ', ""),
                type_text: ty.to_token_stream().to_string().replace(' ', ""),
            });
        }
    }
    let return_type = match &sig.output {
        ReturnType::Default => None,
        ReturnType::Type(_, ty) => Some(ty.to_token_stream().to_string().replace(' ', "")),
    };
    CapturedFunction {
        qualified_name: qualified_name.to_string(),
        file_path: file_path.to_string(),
        parameters,
        return_type,
    }
}

/// Walk a captured function signature and produce OpenAPI-style parameter
/// entries plus an optional request-body and response type, using the
/// extractor conventions of the named framework.
fn extract_handler_signature(
    function: &CapturedFunction,
    framework: &str,
    route_path: &str,
) -> (Vec<EndpointParameter>, Option<String>, Option<String>) {
    let mut parameters = Vec::new();
    let mut request_body_type = None;

    for param in &function.parameters {
        let type_text = &param.type_text;
        let inner = generic_inner_from_text(type_text);

        match framework {
            FRAMEWORK_AXUM => {
                if type_text.starts_with("Path<") || type_text.starts_with("axum::extract::Path<")
                {
                    parameters.extend(synthesize_path_params(
                        route_path,
                        inner.as_deref().unwrap_or(type_text),
                    ));
                } else if type_text.starts_with("Query<")
                    || type_text.starts_with("axum::extract::Query<")
                {
                    parameters.push(EndpointParameter {
                        name: param.pattern_text.clone(),
                        location: "query".to_string(),
                        type_name: inner.unwrap_or_else(|| type_text.clone()),
                    });
                } else if type_text.starts_with("Json<")
                    || type_text.starts_with("axum::Json<")
                    || type_text.starts_with("axum::extract::Json<")
                {
                    request_body_type = inner.or_else(|| Some(type_text.clone()));
                }
            }
            FRAMEWORK_ACTIX => {
                if type_text.starts_with("web::Path<") {
                    parameters.extend(synthesize_path_params(
                        route_path,
                        inner.as_deref().unwrap_or(type_text),
                    ));
                } else if type_text.starts_with("web::Query<") {
                    parameters.push(EndpointParameter {
                        name: param.pattern_text.clone(),
                        location: "query".to_string(),
                        type_name: inner.unwrap_or_else(|| type_text.clone()),
                    });
                } else if type_text.starts_with("web::Json<") {
                    request_body_type = inner.or_else(|| Some(type_text.clone()));
                } else if type_text.starts_with("web::Form<") {
                    request_body_type = inner.or_else(|| Some(type_text.clone()));
                }
            }
            FRAMEWORK_ROCKET => {
                if type_text.starts_with("Json<") || type_text.starts_with("rocket::serde::json::Json<")
                {
                    request_body_type = inner.or_else(|| Some(type_text.clone()));
                } else if type_text.starts_with("Form<") || type_text.starts_with("rocket::form::Form<")
                {
                    request_body_type = inner.or_else(|| Some(type_text.clone()));
                } else {
                    // Bare-name rocket params: parameter named in the
                    // route path becomes a path param of this type.
                    let name = &param.pattern_text;
                    if route_path.contains(&format!("<{}>", name)) {
                        parameters.push(EndpointParameter {
                            name: name.clone(),
                            location: "path".to_string(),
                            type_name: type_text.clone(),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    let response_type = function
        .return_type
        .as_ref()
        .map(|ty| simplify_return_type(ty));

    (parameters, request_body_type, response_type)
}

/// `Path<i32>` → `Some("i32")`; `Path<(i32, String)>` → `Some("(i32,String)")`.
fn generic_inner_from_text(type_text: &str) -> Option<String> {
    let open = type_text.find('<')?;
    let close = type_text.rfind('>')?;
    if close <= open + 1 {
        return None;
    }
    Some(type_text[open + 1..close].to_string())
}

/// Map a single Rust type pulled out of `Path<T>` into one or more
/// OpenAPI-style path parameters, named after the placeholders in the
/// route path. `Path<i32>` with route `/users/:id` → one param named
/// `id` of type `i32`. Tuple `Path<(i32, String)>` with `/x/:a/:b` →
/// two params zipped against the placeholders.
fn synthesize_path_params(route_path: &str, type_inner: &str) -> Vec<EndpointParameter> {
    let names = extract_path_placeholders(route_path);
    if names.is_empty() {
        return Vec::new();
    }
    let tuple = type_inner.trim();
    let types: Vec<String> = if tuple.starts_with('(') && tuple.ends_with(')') {
        tuple[1..tuple.len() - 1]
            .split(',')
            .map(|piece| piece.trim().to_string())
            .filter(|piece| !piece.is_empty())
            .collect()
    } else {
        vec![tuple.to_string()]
    };
    names
        .into_iter()
        .enumerate()
        .map(|(idx, name)| EndpointParameter {
            name,
            location: "path".to_string(),
            type_name: types.get(idx).cloned().unwrap_or_else(|| tuple.to_string()),
        })
        .collect()
}

/// Return the names of path placeholders in a route. Recognises axum's
/// `:name` and actix/rocket's `{name}` and rocket's `<name>` shapes.
fn extract_path_placeholders(route_path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = route_path.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            ':' => {
                let mut name = String::new();
                while let Some(&peek) = chars.peek() {
                    if peek.is_alphanumeric() || peek == '_' {
                        name.push(peek);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if !name.is_empty() {
                    out.push(name);
                }
            }
            '{' | '<' => {
                let closer = if ch == '{' { '}' } else { '>' };
                let mut name = String::new();
                while let Some(&peek) = chars.peek() {
                    if peek == closer {
                        chars.next();
                        break;
                    }
                    name.push(peek);
                    chars.next();
                }
                let trimmed = name
                    .split(|c: char| c == ':' || c == '.' || c == ' ')
                    .next()
                    .unwrap_or("");
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
            }
            _ => {}
        }
    }
    out
}

/// `Result<Json<User>, StatusCode>` → `User`. Strips known wrappers
/// (`Result`, `Json`, `axum::Json`, `actix_web::HttpResponse`) so what's
/// returned is the application-level response type.
fn simplify_return_type(return_type: &str) -> String {
    let mut current = return_type.trim().to_string();
    let wrappers = [
        "Result<",
        "axum::response::Result<",
        "Json<",
        "axum::Json<",
        "actix_web::Json<",
        "web::Json<",
        "rocket::serde::json::Json<",
    ];
    'outer: loop {
        for wrapper in &wrappers {
            if current.starts_with(wrapper) {
                let inner = match generic_inner_from_text(&current) {
                    Some(value) => value,
                    None => break 'outer,
                };
                // For Result<T, E>, keep only the Ok arm.
                if wrapper.starts_with("Result<")
                    || wrapper.starts_with("axum::response::Result<")
                {
                    let ok_arm = ok_arm_of_result(&inner);
                    current = ok_arm.trim().to_string();
                } else {
                    current = inner.trim().to_string();
                }
                continue 'outer;
            }
        }
        break;
    }
    current
}

/// Split a `Result<Ok, Err>` inner string at the top-level comma so we
/// can extract just the Ok arm. Tracks angle-bracket depth to avoid
/// splitting inside nested generics.
fn ok_arm_of_result(inner: &str) -> String {
    let mut depth = 0i32;
    let mut split_at = None;
    for (idx, ch) in inner.char_indices() {
        match ch {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                split_at = Some(idx);
                break;
            }
            _ => {}
        }
    }
    match split_at {
        Some(idx) => inner[..idx].to_string(),
        None => inner.to_string(),
    }
}

// ─── endpoint resolution ────────────────────────────────────────────────

/// Compose nested router fragments into concrete `ApiEndpoint` entries
/// and enrich each with handler signature information.
fn resolve_endpoints(
    builders: &BTreeMap<String, RouterBuilder>,
    functions: &BTreeMap<String, CapturedFunction>,
) -> Vec<ApiEndpoint> {
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for builder in builders.values() {
        for fragment in &builder.fragments {
            if let RouteFragment::Nest { sub_builder, .. } = fragment
                && let Some(matched) = lookup_builder_key(builders, sub_builder)
            {
                referenced.insert(matched);
            }
        }
    }
    let roots: Vec<&RouterBuilder> = builders
        .values()
        .filter(|builder| !referenced.contains(&builder.key))
        .collect();
    let roots: Vec<&RouterBuilder> = if roots.is_empty() {
        builders.values().collect()
    } else {
        roots
    };

    let mut endpoints = Vec::new();
    let mut seen_ids: HashMap<String, usize> = HashMap::new();
    for root in roots {
        let mut visited = BTreeSet::new();
        resolve_from_builder(
            builders,
            functions,
            root,
            "",
            &mut visited,
            &mut endpoints,
            &mut seen_ids,
        );
    }
    endpoints
}

fn resolve_from_builder(
    builders: &BTreeMap<String, RouterBuilder>,
    functions: &BTreeMap<String, CapturedFunction>,
    builder: &RouterBuilder,
    prefix: &str,
    visited: &mut BTreeSet<String>,
    out: &mut Vec<ApiEndpoint>,
    seen_ids: &mut HashMap<String, usize>,
) {
    if !visited.insert(builder.key.clone()) {
        return;
    }
    for fragment in &builder.fragments {
        match fragment {
            RouteFragment::Route {
                method,
                path,
                handler,
                position,
            } => {
                // Attribute-macro builders use an empty handler string —
                // the builder key (the handler's own qualified name) is
                // the handler. Concrete framework routes carry a short
                // handler name we need to qualify against captured
                // declarations.
                let qualified_handler = if handler.is_empty() {
                    builder.key.clone()
                } else {
                    qualify_handler(handler, functions, &builder.file_path)
                        .unwrap_or_else(|| handler.clone())
                };
                let full_path = join_prefix(prefix, path);
                let base_id = stable_id(
                    "api-endpoint",
                    &[
                        &builder.package_path,
                        method,
                        &full_path,
                        &qualified_handler,
                        &builder.file_path,
                    ],
                );
                let counter = seen_ids.entry(base_id.clone()).or_insert(0);
                let id = if *counter == 0 {
                    base_id.clone()
                } else {
                    format!("{}-{}", base_id, *counter)
                };
                *counter += 1;

                let (params, body, response) = match functions.get(&qualified_handler) {
                    Some(function) => {
                        extract_handler_signature(function, &builder.framework, &full_path)
                    }
                    None => (Vec::new(), None, None),
                };

                out.push(ApiEndpoint {
                    id,
                    method: method.clone(),
                    path: full_path,
                    framework: builder.framework.clone(),
                    handler: qualified_handler,
                    package_path: builder.package_path.clone(),
                    purl: String::new(),
                    file_path: builder.file_path.clone(),
                    position: position.clone(),
                    parameters: params,
                    request_body_type: body,
                    response_type: response,
                    properties: IndexMap::new(),
                });
            }
            RouteFragment::Nest {
                prefix: nest_prefix,
                sub_builder,
                position: _,
            } => {
                let new_prefix = join_prefix(prefix, nest_prefix);
                if let Some(matched_key) = lookup_builder_key(builders, sub_builder)
                    && let Some(sub) = builders.get(&matched_key)
                {
                    resolve_from_builder(
                        builders,
                        functions,
                        sub,
                        &new_prefix,
                        visited,
                        out,
                        seen_ids,
                    );
                }
            }
        }
    }
    visited.remove(&builder.key);
}

/// Map a short handler name (`get_user` or `handlers::users::get_user`)
/// onto a full qualified name from the captured functions table.
/// Preference order:
///   1. exact qualified-name match
///   2. tail-segment match in the same file as the route registration
///   3. tail-segment match in any file (first match wins)
///
/// Same-file preference matters when multiple frameworks each define a
/// handler with the same short name (e.g. axum_routes::list_users vs
/// actix_routes::list_users): the router-building file unambiguously
/// belongs to one of them.
fn qualify_handler(
    short: &str,
    functions: &BTreeMap<String, CapturedFunction>,
    route_file_path: &str,
) -> Option<String> {
    if functions.contains_key(short) {
        return Some(short.to_string());
    }
    let suffix = format!("::{}", short.trim_start_matches("::"));
    let mut same_file_match: Option<String> = None;
    let mut any_match: Option<String> = None;
    for (key, function) in functions {
        if !key.ends_with(&suffix) {
            continue;
        }
        if function.file_path == route_file_path {
            same_file_match = Some(key.clone());
            break;
        }
        if any_match.is_none() {
            any_match = Some(key.clone());
        }
    }
    same_file_match.or(any_match)
}

fn lookup_builder_key(
    builders: &BTreeMap<String, RouterBuilder>,
    reference: &str,
) -> Option<String> {
    for key in builders.keys() {
        if key == reference {
            return Some(key.clone());
        }
        if key
            .rsplit("::")
            .next()
            .is_some_and(|tail| tail == reference)
        {
            return Some(key.clone());
        }
    }
    None
}

/// Type used internally for actix-chain dispatch; kept inhabited so
/// downstream pattern matches in the resolution path stay exhaustive
/// even on enum extensions.
#[allow(dead_code)]
type _UnusedGenericArgument = GenericArgument;
#[allow(dead_code)]
type _UnusedPathArguments = PathArguments;
#[allow(dead_code)]
type _UnusedType = Type;
