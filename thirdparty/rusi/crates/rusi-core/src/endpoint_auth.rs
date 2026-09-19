//! Authentication evidence for an HTTP route, read from the middleware the
//! route actually carries.
//!
//! Every API below was read from the framework's own reference, because the
//! two frameworks differ in exactly the place that matters:
//!
//! **axum** — `Router::route_layer` is documented as *the* method for
//! authorization:
//!
//! > "This works similarly to `Router::layer` except the middleware will only
//! > run if the request matches a route. This is useful for middleware that
//! > return early (such as authorization) which might otherwise convert a
//! > `404 Not Found` into a `401 Unauthorized`."
//!
//! `layer` applies to every request including unmatched ones; `route_layer`
//! only to matched routes. Both are recorded, and the source names which.
//! Both apply to the routes declared BEFORE them in the builder chain, which
//! is why the walk applies a layer only to the fragments already emitted.
//!
//! **actix-web** — `App::wrap(mw)` and `Scope::wrap(mw)` register middleware
//! "across all requests managed by the `App`", so a wrap applies to the whole
//! scope it sits on rather than to one route.
//!
//! The contract this follows: an empty result is **not** a denial. A route
//! with no recognized middleware emits nothing, which reads as unknown — a
//! route may sit behind a tower layer rusi does not model.

/// Name fragments that make a middleware an AUTHENTICATION middleware rather
/// than tracing, CORS or compression. Matched on the lower-cased callee.
///
/// This list is the honest weak point and is treated as one: a hit produces
/// evidence naming the middleware so a reader can judge it, and a miss
/// produces nothing rather than "anonymous".
const AUTH_TOKENS: &[&str] = &[
    "auth",
    "authn",
    "authz",
    "jwt",
    "oauth",
    "oidc",
    "bearer",
    "token",
    "login",
    "session",
    "principal",
    "identity",
    "claims",
    "rbac",
    "casbin",
    "permission",
    "require",
    "protected",
    "validator",
    "apikey",
    "basicauth",
];

/// Names that contain an auth token but declare the INVERSE. `NoAuth` and
/// `SkipAuth` must never read as a requirement.
const AUTH_EXCLUDE: &[&str] = &[
    "noauth",
    "skipauth",
    "withoutauth",
    "unauthenticated",
    "anonymous",
    "optionalauth",
];

/// Does this middleware name declare an authentication requirement?
pub(crate) fn is_auth_middleware_name(name: &str) -> bool {
    // Separators are stripped before matching: `skip_auth`, `skip-auth` and
    // `SkipAuth` are one name in three spellings, and an exclusion list that
    // only knew the third would read the other two as a REQUIREMENT — the
    // exact inversion this list exists to prevent.
    let lower: String = name
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if lower.is_empty() {
        return false;
    }
    if AUTH_EXCLUDE.iter().any(|bad| lower.contains(bad)) {
        return false;
    }
    AUTH_TOKENS.iter().any(|tok| lower.contains(tok))
}

/// Render one middleware expression as a declaration, or `None` when it
/// names nothing this vocabulary recognizes.
pub(crate) fn auth_declaration(name: &str) -> Option<String> {
    if is_auth_middleware_name(name) {
        Some(format!("middleware({name})"))
    } else {
        None
    }
}

/// Sorted, de-duplicated declarations.
pub(crate) fn dedupe_auth(mut decls: Vec<String>) -> Vec<String> {
    decls.sort();
    decls.dedup();
    decls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_authentication_middleware() {
        assert!(is_auth_middleware_name("RequireAuth"));
        assert!(is_auth_middleware_name("jwt_middleware"));
        assert!(is_auth_middleware_name("HttpAuthentication"));
        assert!(is_auth_middleware_name("ValidateJwtLayer"));
    }

    #[test]
    fn rejects_middleware_that_is_not_authentication() {
        assert!(!is_auth_middleware_name("TraceLayer"));
        assert!(!is_auth_middleware_name("CorsLayer"));
        assert!(!is_auth_middleware_name("CompressionLayer"));
        assert!(!is_auth_middleware_name(""));
    }

    /// The inverse marker is the case a substring match gets wrong: `NoAuth`
    /// contains "auth" and declares the opposite.
    #[test]
    fn rejects_the_inverse_marker() {
        assert!(!is_auth_middleware_name("NoAuth"));
        assert!(!is_auth_middleware_name("skip_auth"));
        assert!(!is_auth_middleware_name("OptionalAuth"));
    }
}
