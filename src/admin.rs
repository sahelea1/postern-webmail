//! The admin console: a second, smaller HTTP server on its own port, bound to
//! loopback by default. It has no password. `postern admin-link` writes a
//! single-use token into the data directory and prints a link; opening that
//! link starts a two-hour session. Whoever can run that command can already
//! edit the files, so shell access is the root of trust.

use crate::{
    assets::{self, AdminWeb},
    backend::{imap, tls_config},
    config::{Protocol, Security, ServerCfg, Servers},
    error::{Error, Result},
    seal,
    state::{ADMIN_CONTEXT, AppState, cookie},
};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

const COOKIE: &str = "postern_admin";
const SESSION_SECS: u64 = 2 * 3600;
const TOKEN_SECS: u64 = 600;

#[derive(Serialize, Deserialize)]
struct TokenFile {
    hash: String,
    exp: u64,
}

#[derive(Serialize, Deserialize)]
struct AdminSession {
    exp: u64,
}

/// Creates a sign-in token and returns it. Called by the `admin-link` command.
pub fn mint_token(data_dir: &Path) -> std::result::Result<String, String> {
    let token = seal::hex(&seal::random_bytes::<24>());
    let file = TokenFile {
        hash: seal::hex(&Sha256::digest(token.as_bytes())),
        exp: seal::unix_now() + TOKEN_SECS,
    };
    let path = data_dir.join("admin.token");
    std::fs::write(&path, serde_json::to_vec(&file).unwrap())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(token)
}

pub fn router(st: AppState) -> Router {
    Router::new()
        .route("/login", get(login))
        .route("/api/state", get(state))
        .route("/api/servers", post(save_servers))
        .route("/api/test", post(test_server))
        .route("/api/logout", post(logout))
        .fallback(static_files)
        .layer(middleware::from_fn(guard))
        .with_state(st)
}

async fn guard(req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        let h = req.headers();
        let custom = h.get("x-postern").and_then(|v| v.to_str().ok()) == Some("1");
        let site_ok = matches!(
            h.get("sec-fetch-site").and_then(|v| v.to_str().ok()),
            None | Some("same-origin")
        );
        if !(custom && site_ok) {
            return Error::Forbidden.into_response();
        }
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
             img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; \
             require-trusted-types-for 'script'; trusted-types 'none'",
        ),
    );
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

fn authed(st: &AppState, headers: &HeaderMap) -> bool {
    cookie(headers, COOKIE)
        .and_then(|c| st.sealer.open::<AdminSession>(ADMIN_CONTEXT, c))
        .map(|s| s.exp > seal::unix_now())
        .unwrap_or(false)
}

fn require(st: &AppState, headers: &HeaderMap) -> Result<()> {
    if authed(st, headers) {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}

async fn static_files(uri: Uri, headers: HeaderMap) -> Response {
    assets::serve::<AdminWeb>(uri.path(), &headers)
}

#[derive(Deserialize)]
struct LoginQuery {
    token: String,
}

async fn login(State(st): State<AppState>, Query(q): Query<LoginQuery>) -> Response {
    let path = st.cfg.data_dir.join("admin.token");
    let stored: Option<TokenFile> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let presented = seal::hex(&Sha256::digest(q.token.as_bytes()));
    let ok = stored
        .map(|t| t.exp > seal::unix_now() && t.hash == presented)
        .unwrap_or(false);
    if !ok {
        tracing::warn!("admin sign-in with an invalid or expired link");
        return Redirect::to("/?denied=1").into_response();
    }
    // Single use.
    let _ = std::fs::remove_file(&path);
    let sealed = st.sealer.seal(
        ADMIN_CONTEXT,
        &AdminSession {
            exp: seal::unix_now() + SESSION_SECS,
        },
    );
    tracing::info!("admin signed in");
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{COOKIE}={sealed}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECS}"
        ))
        .unwrap(),
    );
    resp
}

async fn logout() -> Response {
    let mut resp = Json(json!({ "ok": true })).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("postern_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),
    );
    resp
}

async fn state(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<Value>> {
    require(&st, &headers)?;
    Ok(Json(json!({
        "servers": st.servers().servers,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": st.started.elapsed().as_secs(),
        "brand": st.cfg.brand,
        "session_hours": st.cfg.session_hours,
        "max_upload_mb": st.cfg.max_upload_mb,
        "trust_proxy": st.cfg.trust_proxy,
        "secure_cookies": st.cfg.secure_cookies,
        "read_only": st.cfg.servers_file.is_some(),
    })))
}

#[derive(Deserialize)]
struct SaveReq {
    servers: Vec<ServerCfg>,
}

async fn save_servers(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SaveReq>,
) -> Result<Json<Value>> {
    require(&st, &headers)?;
    if st.cfg.servers_file.is_some() {
        return Err(Error::bad(
            "The server list is managed by a file (POSTERN_SERVERS_FILE) and cannot be changed here",
        ));
    }
    let mut servers = Servers {
        servers: req.servers,
    };
    servers.normalize();
    servers.validate().map_err(Error::bad)?;
    let path = st.cfg.servers_file();
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, servers.to_toml())
        .and_then(|_| std::fs::rename(&tmp, &path))
        .map_err(|e| Error::Internal(format!("saving {}: {e}", path.display())))?;
    tracing::info!(count = servers.servers.len(), "admin saved the server list");
    *st.servers.write().unwrap() = std::sync::Arc::new(servers);
    Ok(Json(json!({ "ok": true })))
}

/// Checks that a server answers, without signing in to it.
async fn test_server(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(server): Json<ServerCfg>,
) -> Result<Json<Value>> {
    require(&st, &headers)?;
    let mut one = Servers {
        servers: vec![server],
    };
    one.normalize();
    one.validate().map_err(Error::bad)?;
    let s = &one.servers[0];
    let mut checks: Vec<Value> = Vec::new();
    match s.protocol {
        Protocol::Imap => {
            let r = tokio::time::timeout(Duration::from_secs(15), imap::probe(s)).await;
            checks.push(match r {
                Ok(Ok(greeting)) => json!({ "what": "IMAP", "ok": true, "detail": greeting }),
                Ok(Err(e)) => json!({ "what": "IMAP", "ok": false, "detail": detail(&e) }),
                Err(_) => json!({ "what": "IMAP", "ok": false, "detail": "timed out" }),
            });
            let r = tokio::time::timeout(Duration::from_secs(15), smtp_probe(s)).await;
            checks.push(match r {
                Ok(Ok(())) => json!({ "what": "SMTP", "ok": true, "detail": "port answers" }),
                Ok(Err(e)) => json!({ "what": "SMTP", "ok": false, "detail": detail(&e) }),
                Err(_) => json!({ "what": "SMTP", "ok": false, "detail": "timed out" }),
            });
        }
        Protocol::Jmap => {
            let b = st.backend(s, "probe@invalid", "probe", "probe");
            checks.push(match b.verify().await {
                // No valid credentials were sent, so a refusal means the endpoint is alive.
                Err(Error::BadCredentials) | Ok(()) => {
                    json!({ "what": "JMAP", "ok": true, "detail": "session endpoint answers" })
                }
                Err(e) => json!({ "what": "JMAP", "ok": false, "detail": detail(&e) }),
            });
            st.jmap_sessions.forget("probe");
        }
    }
    Ok(Json(json!({ "checks": checks })))
}

fn detail(e: &Error) -> String {
    match e {
        Error::Unreachable(d) | Error::Upstream(d) | Error::Internal(d) | Error::BadRequest(d) => {
            d.clone()
        }
        other => other.to_string(),
    }
}

async fn smtp_probe(s: &ServerCfg) -> Result<()> {
    let stream = tokio::net::TcpStream::connect((s.smtp_host.as_str(), s.smtp_port)).await?;
    if s.smtp_security == Security::Tls {
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from(s.smtp_host.clone())
            .map_err(|_| Error::Unreachable("invalid server name".into()))?;
        tokio_rustls::TlsConnector::from(tls_config(s.tls_insecure))
            .connect(name, stream)
            .await
            .map_err(|e| Error::Unreachable(format!("TLS: {e}")))?;
    }
    Ok(())
}
