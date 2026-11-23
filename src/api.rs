//! The JSON API the web client talks to. Every route except the public
//! configuration and sign-in requires a valid sealed session cookie, and
//! every state-changing route passes the cross-site checks in `guard`.

use crate::{
    backend::{Flag, Outgoing},
    config::{RemoteImages, normalize_email},
    error::{Error, Result},
    message::{self, Attachment, Compose},
    seal,
    smime::{self, Cert, OwnKey, Security},
    state::{AppState, Auth, ClientIp, SESSION_CONTEXT, SessionData, session_key},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

pub fn router(st: AppState) -> Router {
    let upload_limit = st.cfg.max_upload_mb * 1024 * 1024 + 1024 * 1024;
    Router::new()
        .route("/api/config", get(public_config))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/mailboxes", get(mailboxes))
        .route("/api/mailboxes/create", post(mailbox_create))
        .route("/api/mailboxes/rename", post(mailbox_rename))
        .route("/api/mailboxes/delete", post(mailbox_delete))
        .route("/api/messages", get(messages))
        .route("/api/message", get(message_view))
        .route("/api/message/html", get(message_html))
        .route("/api/message/part", get(message_part))
        .route("/api/message/cid", get(message_cid))
        .route("/api/message/raw", get(message_raw))
        .route("/api/flags", post(flags))
        .route("/api/move", post(move_messages))
        .route("/api/delete", post(delete_messages))
        .route("/api/smime/import", post(smime_import))
        .route("/api/smime/certs", post(smime_certs))
        .route("/api/smime/status", get(smime_status))
        .route(
            "/api/send",
            post(send).layer(DefaultBodyLimit::max(upload_limit)),
        )
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(middleware::from_fn(guard))
        .with_state(st)
}

/// Cross-site request checks for everything that changes state. The session
/// cookie is `SameSite=Strict` already; this is the second and third lock.
async fn guard(req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        let h = req.headers();
        let custom = h.get("x-postern").and_then(|v| v.to_str().ok()) == Some("1");
        let fetch_site = h.get("sec-fetch-site").and_then(|v| v.to_str().ok());
        let site_ok = matches!(fetch_site, None | Some("same-origin"));
        let origin_ok = match (
            h.get(header::ORIGIN).and_then(|v| v.to_str().ok()),
            h.get(header::HOST).and_then(|v| v.to_str().ok()),
        ) {
            (Some(origin), Some(host)) => origin
                .split_once("://")
                .map(|(_, o)| o.eq_ignore_ascii_case(host))
                .unwrap_or(false),
            (Some(_), None) => false,
            (None, _) => true,
        };
        if !(custom && site_ok && origin_ok) {
            return Error::Forbidden.into_response();
        }
    }
    next.run(req).await
}

async fn public_config(State(st): State<AppState>, auth: Result<Auth>) -> Json<Value> {
    Json(json!({
        "signed_in": auth.is_ok(),
        "brand": st.cfg.brand,
        "version": env!("CARGO_PKG_VERSION"),
        "configured": !st.servers().servers.is_empty(),
    }))
}

#[derive(Deserialize)]
struct LoginReq {
    email: String,
    password: String,
}

async fn login(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginReq>,
) -> Result<Response> {
    let who = ip.to_string();
    if !st.limiter.allowed(&who) {
        return Err(Error::RateLimited);
    }
    let email = normalize_email(&req.email).ok_or(Error::BadCredentials)?;
    if req.password.is_empty()
        || req.password.len() > 1024
        || req.password.chars().any(|c| c == '\r' || c == '\n')
    {
        st.limiter.failed(&who);
        return Err(Error::BadCredentials);
    }
    let servers = st.servers();
    let Some(server) = servers.for_email(&email) else {
        st.limiter.failed(&who);
        // Same pause as a wrong password, so the answer does not reveal which domains exist.
        tokio::time::sleep(Duration::from_millis(400)).await;
        return Err(Error::UnknownDomain);
    };
    let sid = seal::hex(&seal::random_bytes::<16>());
    let key = session_key(&sid, &server.id);
    match st
        .backend(server, &email, &req.password, &key)
        .verify()
        .await
    {
        Ok(()) => {}
        Err(Error::BadCredentials) => {
            st.limiter.failed(&who);
            tracing::info!(server = %server.id, ip = %who, "sign-in refused by the mail server");
            tokio::time::sleep(Duration::from_millis(400)).await;
            return Err(Error::BadCredentials);
        }
        Err(e) => return Err(e),
    }
    st.limiter.succeeded(&who);
    let ttl = st.cfg.session_hours * 3600;
    let data = SessionData {
        sid,
        server: server.id.clone(),
        email: email.clone(),
        pass: req.password,
        exp: seal::unix_now() + ttl,
    };
    let sealed = st.sealer.seal(SESSION_CONTEXT, &data);
    tracing::info!(server = %server.id, ip = %who, "signed in");
    let mut resp = Json(json!({ "email": email })).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&st.session_cookie(&sealed, ttl))
            .map_err(|e| Error::Internal(e.to_string()))?,
    );
    Ok(resp)
}

async fn logout(State(st): State<AppState>, auth: Result<Auth>) -> Response {
    if let Ok(a) = auth {
        st.revoke(&a.data.sid, a.data.exp);
        st.imap_pool.forget(&a.key);
        st.jmap_sessions.forget(&a.key);
        st.raw_cache.drop_prefix(&format!("{}|", a.key));
    }
    // No Clear-Site-Data here: browsers hold the response until their cache
    // is cleared, which took many seconds, and "storage" also wiped the
    // settings and S/MIME keys kept in this browser. API responses are
    // never cached (no-store), so there is nothing to clear.
    let mut resp = Json(json!({ "ok": true })).into_response();
    if let Ok(v) = HeaderValue::from_str(&st.session_cookie("", 0)) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

async fn me(State(st): State<AppState>, auth: Auth) -> Json<Value> {
    Json(json!({
        "email": auth.data.email,
        "server": if auth.server.name.is_empty() { auth.server.id.clone() } else { auth.server.name.clone() },
        "protocol": auth.server.protocol,
        "remote_images": auth.server.remote_images,
        "max_upload_mb": st.cfg.max_upload_mb,
        "brand": st.cfg.brand,
        "version": env!("CARGO_PKG_VERSION"),
        "expires": auth.data.exp,
    }))
}

async fn mailboxes(State(st): State<AppState>, auth: Auth) -> Result<Json<Value>> {
    Ok(Json(
        json!({ "mailboxes": auth.backend(&st).mailboxes().await? }),
    ))
}

#[derive(Deserialize)]
struct MailboxCreate {
    name: String,
    parent: Option<String>,
}

async fn mailbox_create(
    State(st): State<AppState>,
    auth: Auth,
    Json(r): Json<MailboxCreate>,
) -> Result<Json<Value>> {
    auth.backend(&st)
        .create_mailbox(r.parent.as_deref(), &r.name)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct MailboxRename {
    id: String,
    name: String,
}

async fn mailbox_rename(
    State(st): State<AppState>,
    auth: Auth,
    Json(r): Json<MailboxRename>,
) -> Result<Json<Value>> {
    auth.backend(&st).rename_mailbox(&r.id, &r.name).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct MailboxDelete {
    id: String,
}

async fn mailbox_delete(
    State(st): State<AppState>,
    auth: Auth,
    Json(r): Json<MailboxDelete>,
) -> Result<Json<Value>> {
    auth.backend(&st).delete_mailbox(&r.id).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct ListQuery {
    mailbox: String,
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
    q: Option<String>,
}

async fn messages(
    State(st): State<AppState>,
    auth: Auth,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 100);
    let page = auth
        .backend(&st)
        .list(&q.mailbox, q.offset.min(1_000_000), limit, q.q.as_deref())
        .await?;
    Ok(Json(json!(page)))
}

#[derive(Deserialize)]
struct MsgRef {
    mailbox: String,
    id: String,
}

/// Fetches a message's raw bytes, through the two-minute cache.
async fn raw_of(st: &AppState, auth: &Auth, mailbox: &str, id: &str) -> Result<Bytes> {
    let key = format!("{}|{}|{}", auth.key, mailbox, id);
    if let Some(b) = st.raw_cache.get(&key) {
        return Ok(b);
    }
    let raw = auth.backend(st).raw(mailbox, id).await?;
    st.raw_cache.put(key, raw.clone());
    Ok(raw)
}

/// The browser sends the user's sealed S/MIME key in this header with the
/// requests that need it. Only this server can open it.
const KEY_HEADER: &str = "x-postern-key";

/// `Ok(None)`: no key sent. `Err`: a key was sent that this server cannot
/// open (the server key changed, or it belongs to another address).
fn own_key(st: &AppState, auth: &Auth, headers: &HeaderMap) -> std::result::Result<Option<OwnKey>, ()> {
    match headers
        .get(KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    {
        None => Ok(None),
        Some(v) => smime::open_key(&st.sealer, v, &auth.data.email)
            .map(Some)
            .ok_or(()),
    }
}

fn from_addresses(raw: &[u8]) -> Vec<String> {
    message::parse(raw)
        .map(|m| {
            message::addrs(m.from())
                .into_iter()
                .map(|a| a.email.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

/// A message and, for S/MIME, its verified or decrypted body.
struct Opened {
    raw: Bytes,
    inner: Option<Bytes>,
    security: Option<Security>,
    encrypted: bool,
}

impl Opened {
    fn body(&self) -> &[u8] {
        self.inner.as_deref().unwrap_or(&self.raw)
    }
}

/// Fetches a message and unwraps its S/MIME layers. The unwrapped body goes
/// into the same two-minute memory cache as the message, so the mail frame
/// and its images can load without sending the key again. With `report`
/// the signature is always checked anew.
async fn open_message(
    st: &AppState,
    auth: &Auth,
    mailbox: &str,
    id: &str,
    key: Option<OwnKey>,
    report: bool,
) -> Result<Opened> {
    let raw = raw_of(st, auth, mailbox, id).await?;
    let Some(kind) = smime::kind_of(&raw) else {
        return Ok(Opened {
            raw,
            inner: None,
            security: None,
            encrypted: false,
        });
    };
    let encrypted = kind == "encrypted";
    let cache_key = format!("{}|{}|{}|inner", auth.key, mailbox, id);
    if !report {
        if let Some(inner) = st.raw_cache.get(&cache_key) {
            return Ok(Opened {
                raw,
                inner: Some(inner),
                security: None,
                encrypted,
            });
        }
    }
    let st2 = st.clone();
    let raw2 = raw.clone();
    let un = tokio::task::spawn_blocking(move || {
        let from = from_addresses(&raw2);
        smime::unwrap(&raw2, &from, key.as_ref(), &st2.trust)
    })
    .await
    .map_err(|e| Error::Internal(e.to_string()))?;
    let inner = un.inner.map(Bytes::from);
    if let Some(i) = &inner {
        st.raw_cache.put(cache_key, i.clone());
    }
    Ok(Opened {
        raw,
        inner,
        security: Some(un.security),
        encrypted,
    })
}

fn cid_prefix(mailbox: &str, id: &str) -> String {
    format!(
        "/api/message/cid?mailbox={}&id={}&cid=",
        utf8_percent_encode(mailbox, NON_ALPHANUMERIC),
        utf8_percent_encode(id, NON_ALPHANUMERIC)
    )
}

async fn message_view(
    State(st): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Query(r): Query<MsgRef>,
) -> Result<Json<Value>> {
    let key = own_key(&st, &auth, &headers);
    let key_invalid = key.is_err();
    let o = open_message(&st, &auth, &r.mailbox, &r.id, key.ok().flatten(), true).await?;
    let mut view = message::view(&o.raw, o.inner.as_deref())?;
    if o.encrypted && o.inner.is_none() {
        // Nothing to show but the notice; the ciphertext is not an attachment.
        view.text.clear();
        view.attachments.clear();
        view.has_html = false;
        view.remote_images = false;
    }
    let mut v = json!(view);
    v["size"] = json!(o.raw.len());
    v["can_load_images"] = json!(auth.server.remote_images == RemoteImages::Ask);
    v["security"] = json!(o.security.unwrap_or_default());
    v["key_invalid"] = json!(key_invalid);
    Ok(Json(v))
}

fn untrusted_headers(resp: &mut Response) {
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox; frame-ancestors 'none'"),
    );
}

#[derive(Deserialize)]
struct HtmlQuery {
    mailbox: String,
    id: String,
    #[serde(default)]
    images: u8,
}

/// The message body as a document for the sandboxed mail frame. Its own
/// policy forbids script outright and decides whether images may load.
async fn message_html(
    State(st): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Query(q): Query<HtmlQuery>,
) -> Result<Response> {
    let key = own_key(&st, &auth, &headers).ok().flatten();
    let o = open_message(&st, &auth, &q.mailbox, &q.id, key, false).await?;
    if o.encrypted && o.inner.is_none() {
        return Err(Error::NotFound);
    }
    let remote = q.images == 1 && auth.server.remote_images == RemoteImages::Ask;
    let doc = message::html_view(o.body(), remote, &cid_prefix(&q.mailbox, &q.id))?;
    let csp = format!(
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:{}; font-src 'none'; \
         form-action 'none'; base-uri 'none'; frame-ancestors 'self'; \
         sandbox allow-same-origin allow-popups allow-popups-to-escape-sandbox",
        if remote { " https: http:" } else { "" }
    );
    let mut resp = (StatusCode::OK, doc).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&csp).unwrap(),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(resp)
}

fn disposition(name: &str) -> HeaderValue {
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let ascii = if ascii.trim().is_empty() {
        "attachment".to_string()
    } else {
        ascii
    };
    let v = format!(
        "attachment; filename=\"{}\"; filename*=UTF-8''{}",
        ascii.trim(),
        utf8_percent_encode(name, NON_ALPHANUMERIC)
    );
    HeaderValue::from_str(&v).unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

#[derive(Deserialize)]
struct PartQuery {
    mailbox: String,
    id: String,
    part: u32,
    #[serde(default)]
    inline: u8,
}

async fn message_part(
    State(st): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Query(q): Query<PartQuery>,
) -> Result<Response> {
    let key = own_key(&st, &auth, &headers).ok().flatten();
    let o = open_message(&st, &auth, &q.mailbox, &q.id, key, false).await?;
    if o.encrypted && o.inner.is_none() {
        return Err(Error::NotFound);
    }
    let part = message::part(o.body(), q.part)?;
    // Only raster images may be shown in place; everything else is a download.
    let inline_type = if q.inline == 1 {
        message::sniff_image(&part.data)
    } else {
        None
    };
    let mut resp = Response::new(Body::from(part.data));
    untrusted_headers(&mut resp);
    let h = resp.headers_mut();
    match inline_type {
        Some(t) => {
            h.insert(header::CONTENT_TYPE, HeaderValue::from_static(t));
        }
        None => {
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            h.insert(header::CONTENT_DISPOSITION, disposition(&part.name));
        }
    }
    Ok(resp)
}

#[derive(Deserialize)]
struct CidQuery {
    mailbox: String,
    id: String,
    cid: String,
}

async fn message_cid(
    State(st): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Query(q): Query<CidQuery>,
) -> Result<Response> {
    let key = own_key(&st, &auth, &headers).ok().flatten();
    let o = open_message(&st, &auth, &q.mailbox, &q.id, key, false).await?;
    if o.encrypted && o.inner.is_none() {
        return Err(Error::NotFound);
    }
    let part = message::cid_image(o.body(), &q.cid)?;
    let mut resp = Response::new(Body::from(part.data));
    untrusted_headers(&mut resp);
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&part.mime).unwrap(),
    );
    Ok(resp)
}

#[derive(Deserialize)]
struct RawQuery {
    mailbox: String,
    id: String,
    #[serde(default)]
    view: u8,
}

async fn message_raw(
    State(st): State<AppState>,
    auth: Auth,
    Query(q): Query<RawQuery>,
) -> Result<Response> {
    let raw = raw_of(&st, &auth, &q.mailbox, &q.id).await?;
    let mut resp = Response::new(Body::from(raw));
    untrusted_headers(&mut resp);
    let h = resp.headers_mut();
    if q.view == 1 {
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    } else {
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        h.insert(header::CONTENT_DISPOSITION, disposition("message.eml"));
    }
    Ok(resp)
}

#[derive(Deserialize)]
struct FlagsReq {
    mailbox: String,
    ids: Vec<String>,
    flag: String,
    on: bool,
}

async fn flags(
    State(st): State<AppState>,
    auth: Auth,
    Json(r): Json<FlagsReq>,
) -> Result<Json<Value>> {
    let flag = Flag::parse(&r.flag).ok_or_else(|| Error::bad("unknown flag"))?;
    auth.backend(&st)
        .set_flag(&r.mailbox, &r.ids, flag, r.on)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct MoveReq {
    mailbox: String,
    ids: Vec<String>,
    dest: String,
}

fn forget_cached(st: &AppState, auth: &Auth, mailbox: &str) {
    st.raw_cache
        .drop_prefix(&format!("{}|{}|", auth.key, mailbox));
}

async fn move_messages(
    State(st): State<AppState>,
    auth: Auth,
    Json(r): Json<MoveReq>,
) -> Result<Json<Value>> {
    if r.dest == r.mailbox {
        return Err(Error::bad("the messages are already in that folder"));
    }
    auth.backend(&st)
        .move_to(&r.mailbox, &r.ids, &r.dest)
        .await?;
    forget_cached(&st, &auth, &r.mailbox);
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct DeleteReq {
    mailbox: String,
    ids: Vec<String>,
    /// The trash folder. Messages go there unless they are in it already or it is absent.
    trash: Option<String>,
}

async fn delete_messages(
    State(st): State<AppState>,
    auth: Auth,
    Json(r): Json<DeleteReq>,
) -> Result<Json<Value>> {
    let b = auth.backend(&st);
    let permanent = match r.trash.as_deref() {
        Some(trash) if trash != r.mailbox => {
            b.move_to(&r.mailbox, &r.ids, trash).await?;
            false
        }
        _ => {
            b.destroy(&r.mailbox, &r.ids).await?;
            true
        }
    };
    forget_cached(&st, &auth, &r.mailbox);
    Ok(Json(json!({ "ok": true, "permanent": permanent })))
}

#[derive(Deserialize)]
struct ForwardRef {
    mailbox: String,
    id: String,
    parts: Vec<u32>,
}

#[derive(Deserialize, Default)]
struct SmimeOpts {
    #[serde(default)]
    sign: bool,
    #[serde(default)]
    encrypt: bool,
    /// Recipient certificates from the browser's store, base64 DER.
    #[serde(default)]
    certs: Vec<String>,
}

#[derive(Deserialize)]
struct SendMeta {
    from_name: Option<String>,
    #[serde(default)]
    to: String,
    #[serde(default)]
    cc: String,
    #[serde(default)]
    bcc: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    text: String,
    in_reply_to: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    /// Save to Drafts instead of sending.
    #[serde(default)]
    draft: bool,
    sent_mailbox: Option<String>,
    drafts_mailbox: Option<String>,
    /// The draft this message replaces; removed afterwards.
    replace_draft: Option<MsgRef>,
    /// The message being answered; flagged as answered afterwards.
    answered: Option<MsgRef>,
    /// Attachments carried over from another message.
    forward: Option<ForwardRef>,
    #[serde(default)]
    smime: SmimeOpts,
}

/// The certificates to encrypt for: the sender's own (for the Sent copy)
/// and the best usable one for every To and Cc address.
fn recipient_certs(certs: &[String], c: &Compose, own: &OwnKey) -> Result<Vec<Cert>> {
    let parsed: Vec<Cert> = certs
        .iter()
        .take(200)
        .filter_map(|b| B64.decode(b.trim()).ok())
        .filter_map(|d| Cert::parse(&d).ok())
        .collect();
    let mut out = vec![own.cert.clone()];
    let mut missing = Vec::new();
    for a in c.to.iter().chain(&c.cc) {
        let e = a.email.to_ascii_lowercase();
        let best = parsed
            .iter()
            .filter(|x| x.emails.contains(&e) && x.can_encrypt())
            .max_by_key(|x| x.not_after());
        match best {
            Some(x) => {
                if !out.iter().any(|o| o.der == x.der) {
                    out.push(x.clone());
                }
            }
            None => missing.push(a.email.clone()),
        }
    }
    if !missing.is_empty() {
        return Err(Error::bad(format!(
            "No usable certificate for {}. Remove these recipients or send without encryption.",
            missing.join(", ")
        )));
    }
    Ok(out)
}

/// Signs and/or encrypts a built message. Returns the copy (with Bcc) and
/// the message as sent (without Bcc); both carry the same protected body.
fn protect(copy: &[u8], key: &OwnKey, sign: bool, recipients: Option<&[Cert]>) -> Result<(Vec<u8>, Vec<u8>)> {
    let (outer, mut entity) = smime::split_message(copy);
    if sign {
        entity = smime::signed_entity(key, &entity)?;
    }
    if let Some(r) = recipients {
        let refs: Vec<&Cert> = r.iter().collect();
        entity = smime::enveloped_entity(&entity, &refs)?;
    }
    let wire = [smime::without_field(&outer, "bcc"), entity.clone()].concat();
    Ok(([outer, entity].concat(), wire))
}

async fn send(
    State(st): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    mut form: Multipart,
) -> Result<Json<Value>> {
    let mut meta: Option<SendMeta> = None;
    let mut attachments: Vec<Attachment> = Vec::new();
    let budget = st.cfg.max_upload_mb * 1024 * 1024;
    let mut used = 0usize;
    while let Some(field) = form.next_field().await? {
        match field.name() {
            Some("meta") => {
                let text = field.text().await?;
                meta = Some(
                    serde_json::from_str(&text)
                        .map_err(|e| Error::bad(format!("invalid request: {e}")))?,
                );
            }
            Some("file") => {
                let name = field.file_name().unwrap_or("attachment").to_string();
                let mime = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let data = field.bytes().await?;
                used += data.len();
                if used > budget || attachments.len() >= 50 {
                    return Err(Error::bad(format!(
                        "attachments are limited to {} MB in total",
                        st.cfg.max_upload_mb
                    )));
                }
                attachments.push(Attachment {
                    name,
                    mime,
                    data: data.to_vec(),
                });
            }
            _ => {}
        }
    }
    let meta = meta.ok_or_else(|| Error::bad("missing message"))?;
    if meta.text.len() > 2 * 1024 * 1024 {
        return Err(Error::bad("the message text is too long"));
    }
    let wants_key = meta.smime.sign || meta.smime.encrypt;
    let key = match own_key(&st, &auth, &headers) {
        Ok(k) => k,
        Err(()) if wants_key => {
            return Err(Error::bad(
                "Your S/MIME key on this device can no longer be used. Import it again in Settings.",
            ));
        }
        Err(()) => None,
    };
    if wants_key && key.is_none() {
        return Err(Error::bad("Import your S/MIME key in Settings first."));
    }
    if let Some(f) = &meta.forward {
        let o = open_message(&st, &auth, &f.mailbox, &f.id, key.clone(), false).await?;
        for p in f.parts.iter().take(50) {
            let part = message::part(o.body(), *p)?;
            used += part.data.len();
            if used > budget {
                return Err(Error::bad(format!(
                    "attachments are limited to {} MB in total",
                    st.cfg.max_upload_mb
                )));
            }
            attachments.push(Attachment {
                name: part.name,
                mime: part.mime,
                data: part.data,
            });
        }
    }
    let compose = Compose {
        from_name: meta.from_name.clone(),
        from_email: auth.data.email.clone(),
        to: message::parse_recipients(&meta.to)?,
        cc: message::parse_recipients(&meta.cc)?,
        bcc: message::parse_recipients(&meta.bcc)?,
        subject: meta.subject.clone(),
        text: meta.text.clone(),
        in_reply_to: meta.in_reply_to.clone(),
        references: meta.references.iter().take(30).cloned().collect(),
        attachments,
    };
    let recipients: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        compose
            .to
            .iter()
            .chain(&compose.cc)
            .chain(&compose.bcc)
            .map(|a| a.email.clone())
            .filter(|e| seen.insert(e.to_ascii_lowercase()))
            .collect()
    };
    if recipients.len() > 100 {
        return Err(Error::bad("at most 100 recipients per message"));
    }
    let message_id = message::new_message_id(&compose.from_email);
    let backend = auth.backend(&st);

    if meta.draft {
        let drafts = meta
            .drafts_mailbox
            .as_deref()
            .ok_or_else(|| Error::bad("this account has no drafts folder"))?;
        let mut copy = message::build(&compose, &message_id, true)?;
        if meta.smime.encrypt {
            // A draft of an encrypted message is kept encrypted, for the sender only.
            let k = key.as_ref().expect("checked above");
            copy = protect(&copy, k, false, Some(&[k.cert.clone()]))?.0;
        }
        backend
            .append(drafts, &copy, &[Flag::Draft, Flag::Seen])
            .await?;
    } else {
        if recipients.is_empty() {
            return Err(Error::bad("add at least one recipient"));
        }
        let (wire, copy) = match &key {
            Some(k) if wants_key => {
                if meta.smime.encrypt && !compose.bcc.is_empty() {
                    return Err(Error::bad(
                        "Encrypted messages cannot have Bcc recipients: the encryption would name them to everyone. Send them a separate message.",
                    ));
                }
                let certs = if meta.smime.encrypt {
                    Some(recipient_certs(&meta.smime.certs, &compose, k)?)
                } else {
                    None
                };
                let built = message::build(&compose, &message_id, true)?;
                let (copy, wire) = protect(&built, k, meta.smime.sign, certs.as_deref())?;
                (wire, copy)
            }
            _ => (
                message::build(&compose, &message_id, false)?,
                message::build(&compose, &message_id, true)?,
            ),
        };
        let out = Outgoing {
            from: compose.from_email.clone(),
            recipients,
            wire,
            copy,
            sent_mailbox: meta.sent_mailbox.clone(),
        };
        backend.send(&out).await?;
        tracing::info!(
            server = %auth.server.id,
            recipients = out.recipients.len(),
            bytes = out.wire.len(),
            signed = meta.smime.sign,
            encrypted = meta.smime.encrypt,
            "message sent"
        );
        if let Some(a) = &meta.answered {
            // Sending succeeded; a failed flag update is not worth an error.
            let _ = backend
                .set_flag(&a.mailbox, &[a.id.clone()], Flag::Answered, true)
                .await;
        }
    }
    if let Some(d) = &meta.replace_draft {
        let _ = backend.destroy(&d.mailbox, &[d.id.clone()]).await;
        forget_cached(&st, &auth, &d.mailbox);
    }
    Ok(Json(json!({ "ok": true, "draft": meta.draft })))
}

// ---- S/MIME ------------------------------------------------------------------

/// Reads the user's .p12/.pfx file and returns the key sealed for this
/// server and this address. Neither the file nor its password is kept.
async fn smime_import(State(st): State<AppState>, auth: Auth, mut form: Multipart) -> Result<Json<Value>> {
    let mut data: Option<Bytes> = None;
    let mut password = String::new();
    while let Some(field) = form.next_field().await? {
        match field.name() {
            Some("file") => data = Some(field.bytes().await?),
            Some("password") => password = field.text().await?,
            _ => {}
        }
    }
    let data = data.ok_or_else(|| Error::bad("Choose a .p12 or .pfx file."))?;
    if data.is_empty() || data.len() > 128 * 1024 {
        return Err(Error::bad("This does not look like a key file."));
    }
    let st2 = st.clone();
    let email = auth.data.email.clone();
    let imp = tokio::task::spawn_blocking(move || {
        smime::import(&st2.sealer, &st2.trust, &data, &password, &email)
    })
    .await
    .map_err(|e| Error::Internal(e.to_string()))??;
    tracing::info!(server = %auth.server.id, "S/MIME key imported");
    Ok(Json(json!({
        "sealed": imp.sealed,
        "cert": imp.cert,
        "email_match": imp.email_match,
        "can_decrypt": imp.can_decrypt,
    })))
}

#[derive(Deserialize)]
struct CertsReq {
    /// The file's bytes, base64: PEM, DER, or a .p7c/.p7b bundle.
    data: String,
}

/// Reads certificates for the browser's store and says how far they are trusted.
async fn smime_certs(State(st): State<AppState>, _auth: Auth, Json(r): Json<CertsReq>) -> Result<Json<Value>> {
    let bytes = B64
        .decode(r.data.trim())
        .map_err(|_| Error::bad("The file could not be read."))?;
    let certs = smime::certificates_from(&bytes);
    if certs.is_empty() {
        return Err(Error::bad("No certificate was found in this file."));
    }
    let ders: Vec<&[u8]> = certs.iter().map(|c| c.der.as_slice()).collect();
    let infos: Vec<smime::CertInfo> = certs
        .iter()
        .map(|c| {
            let others: Vec<&[u8]> = ders.iter().copied().filter(|d| *d != c.der.as_slice()).collect();
            c.info(&st.trust, &others)
        })
        .collect();
    Ok(Json(json!({ "certs": infos })))
}

/// Whether the key this browser holds can still be opened here.
async fn smime_status(State(st): State<AppState>, auth: Auth, headers: HeaderMap) -> Json<Value> {
    let key = match own_key(&st, &auth, &headers) {
        Ok(Some(_)) => "ok",
        Ok(None) => "none",
        Err(()) => "invalid",
    };
    Json(json!({ "key": key, "anchors": st.trust.len() }))
}

/// Headers every response gets unless a handler already set its own.
pub async fn security_headers(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let mut resp = next.run(req).await;
    let h: &mut HeaderMap = resp.headers_mut();
    let mut default = |name: header::HeaderName, value: &'static str| {
        if !h.contains_key(&name) {
            h.insert(name, HeaderValue::from_static(value));
        }
    };
    default(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    default(header::REFERRER_POLICY, "no-referrer");
    default(header::X_FRAME_OPTIONS, "DENY");
    default(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    );
    default(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        "same-origin",
    );
    default(
        header::HeaderName::from_static("permissions-policy"),
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=(), interest-cohort=()",
    );
    if is_api {
        default(header::CACHE_CONTROL, "no-store");
        default(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'; sandbox",
        );
    } else {
        default(header::CONTENT_SECURITY_POLICY, crate::assets::APP_CSP);
    }
    if st.cfg.secure_cookies {
        default(
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=63072000; includeSubDomains",
        );
    }
    resp
}
