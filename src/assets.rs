//! The web client, compiled into the binary.

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/dist/"]
struct Web;

#[derive(RustEmbed)]
#[folder = "web/admin/"]
pub struct AdminWeb;

/// Policy for the app shell: only its own scripts and styles, no inline code,
/// no foreign origins, and no way to turn a string into markup.
pub const APP_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-src 'self'; \
manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; \
require-trusted-types-for 'script'; trusted-types 'none'";

pub fn serve<E: RustEmbed>(path: &str, headers: &HeaderMap) -> Response {
    let path = path.trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    let Some(file) = E::get(path) else {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    };
    let etag = format!(
        "\"{}\"",
        crate::seal::hex(&file.metadata.sha256_hash()[..12])
    );
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        == Some(etag.as_str())
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    let mut resp = Response::new(Body::from(file.data.into_owned()));
    let h = resp.headers_mut();
    let mime = file.metadata.mimetype();
    let content_type =
        if mime.starts_with("text/") || mime.contains("javascript") || mime.contains("json") {
            format!("{mime}; charset=utf-8")
        } else {
            mime.to_string()
        };
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

pub async fn web(uri: Uri, headers: HeaderMap) -> Response {
    serve::<Web>(uri.path(), &headers)
}

pub async fn healthz() -> &'static str {
    "ok"
}
