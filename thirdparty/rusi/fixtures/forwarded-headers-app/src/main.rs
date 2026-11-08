// Fixture for the forwarded-header rules: request values a client can choose
// through the Forwarded and X-Forwarded-* headers behind a pass-through
// proxy, the config that turns header-derived client IPs on, and the twins
// that must stay quiet. The framework paths are phantom: rusi is
// syntax-based, and the type paths are what the rules match on.

/// The axum Host extractor: previously http-request, now proxy-derived.
///
/// Expect: a proxy-derived -> html-response flow (asserted in lib.rs tests).
async fn axum_host_handler(host: axum::extract::Host) {
    format!("<i>{}</i>", host)
}

/// Header-derived client IPs from the axum-client-ip crate.
///
/// Expect: a proxy-derived -> html-response flow (asserted in lib.rs tests).
async fn insecure_client_ip(ip: axum_client_ip::InsecureClientIp) {
    format!("<i>{:?}</i>", ip)
}

/// Expect: a proxy-derived -> html-response flow (asserted in lib.rs tests).
async fn rightmost_x_forwarded_for(ip: axum_client_ip::RightmostXForwardedFor) {
    format!("<i>{:?}</i>", ip)
}

/// Expect: a proxy-derived -> html-response flow (asserted in lib.rs tests).
async fn x_real_ip(ip: axum_client_ip::XRealIp) {
    format!("<i>{:?}</i>", ip)
}

/// The configured extractor: its source is a header the ClientIpSource layer
/// picks, which a source scan cannot see; ConnectInfo is the one variant that
/// is not a header, and the deployment decides.
///
/// Expect: a proxy-derived -> html-response flow (asserted in lib.rs tests).
async fn configured_client_ip(ip: axum_client_ip::ClientIp) {
    format!("<i>{:?}</i>", ip)
}

/// actix resolves host, scheme and the forwarded client address from the
/// Forwarded and X-Forwarded-* headers (actix-web src/info.rs).
///
/// Expect: a proxy-derived -> html-response flow (asserted in lib.rs tests).
fn actix_connection_info(req: &actix_web::HttpRequest) {
    format!("<i>{}</i>", req.connection_info().host())
}

/// Expect: a proxy-derived -> html-response flow (asserted in lib.rs tests).
fn actix_scheme(req: &actix_web::HttpRequest) {
    format!("<i>{}</i>", req.connection_info().scheme())
}

/// Expect: a proxy-derived -> html-response flow (asserted in lib.rs tests).
fn actix_realip(req: &actix_web::HttpRequest) {
    format!("<i>{:?}</i>", req.connection_info().realip_remote_addr())
}

/// A literal read of a forwarded header.
///
/// Expect: a proxy-derived -> html-response flow (asserted in lib.rs tests).
fn read_x_forwarded_for(req: &actix_web::HttpRequest) {
    format!("<i>{:?}</i>", req.headers().get("x-forwarded-for"))
}

// --- Twins: the same names on unrelated receivers, and the shapes that are
// --- not header-derived.

struct Host;

/// A local type named Host: the rule keys on axum's own path.
///
/// Expect: no proxy-derived -> html-response flow (asserted in lib.rs tests).
async fn twin_host(host: Host) {
    format!("<i>{:?}</i>", host)
}

/// peer_addr is the socket address, which no middleware rewrites.
///
/// Expect: no proxy-derived -> html-response flow (asserted in lib.rs tests).
fn twin_peer_addr(req: &actix_web::HttpRequest) {
    format!("<i>{:?}</i>", req.peer_addr())
}

/// ConnectInfo carries the socket address.
///
/// Expect: no proxy-derived -> html-response flow (asserted in lib.rs tests).
async fn twin_connect_info(addr: axum::extract::ConnectInfo<std::net::SocketAddr>) {
    format!("<i>{:?}</i>", addr)
}

/// A non-literal header name the analysis cannot see.
///
/// Expect: no proxy-derived -> html-response flow (asserted in lib.rs tests).
fn twin_dynamic_header(req: &actix_web::HttpRequest, name: &str) {
    format!("<i>{:?}</i>", req.headers().get(name))
}

/// A header outside the forwarded family.
///
/// Expect: no proxy-derived -> html-response flow (asserted in lib.rs tests).
fn twin_other_header(req: &actix_web::HttpRequest) {
    format!("<i>{:?}</i>", req.headers().get("x-trace"))
}

/// The same get on an unrelated map.
///
/// Expect: no proxy-derived -> html-response flow (asserted in lib.rs tests).
fn twin_map_get(map: &std::collections::HashMap<String, String>) {
    format!("<i>{:?}</i>", map.get("x-forwarded-for"))
}

/// A same-named method on another receiver.
///
/// Expect: no proxy-derived -> html-response flow (asserted in lib.rs tests).
fn twin_host_method(cfg: &Config) {
    format!("<i>{}</i>", cfg.host())
}

struct Config;

impl Config {
    fn host(&self) -> &str {
        "example.com"
    }
}

/// ClientIpSource naming a header turns on header-derived client IPs.
///
/// Expect: a trusted-proxy-config signal (asserted in lib.rs tests).
fn router_with_layer() -> axum::routing::Router<()> {
    axum::routing::Router::new()
        .layer(axum_client_ip::ClientIpSource::RightmostXForwardedFor.into_extension())
}

/// ConnectInfo is the socket address, not a header, so nothing turns on.
///
/// Expect: no trusted-proxy-config signal (asserted in lib.rs tests).
fn router_with_connect_info() -> axum::routing::Router<()> {
    axum::routing::Router::new()
        .layer(axum_client_ip::ClientIpSource::ConnectInfo.into_extension())
}

