//! Shared application state, the session extractor and small in-memory helpers.
//! Nothing here is persisted: a restart forgets connections and caches, while
//! sessions survive because they live in the browser's sealed cookie.

use crate::{
    backend::{Backend, imap, jmap},
    config::{Config, Protocol, ServerCfg, Servers, UsernameStyle},
    error::{Error, Result},
    seal::{self, Sealer},
    smime::Trust,
};
use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, header, request::Parts},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

pub const SESSION_CONTEXT: &str = "postern-session-v1";
pub const ADMIN_CONTEXT: &str = "postern-admin-v1";

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionData {
    pub sid: String,
    pub server: String,
    pub email: String,
    pub pass: String,
    /// Unix time after which the session is refused.
    pub exp: u64,
}

pub struct Inner {
    pub cfg: Config,
    pub servers: RwLock<Arc<Servers>>,
    pub sealer: Sealer,
    pub limiter: Limiter,
    pub imap_pool: imap::Pool,
    pub jmap_sessions: jmap::Sessions,
    pub http: jmap::HttpClients,
    pub raw_cache: RawCache,
    /// Trust anchors for S/MIME signatures.
    pub trust: Trust,
    /// Sessions that signed out before their cookie expired: session id -> expiry.
    /// Kept in memory only, so a restart forgets it; the cookie's own expiry still applies.
    pub revoked: Mutex<HashMap<String, u64>>,
    pub started: Instant,
}

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(cfg: Config, servers: Servers, sealer: Sealer, trust: Trust) -> Self {
        AppState(Arc::new(Inner {
            cfg,
            servers: RwLock::new(Arc::new(servers)),
            sealer,
            limiter: Limiter::default(),
            imap_pool: imap::Pool::default(),
            jmap_sessions: jmap::Sessions::default(),
            http: jmap::HttpClients::new(),
            raw_cache: RawCache::default(),
            trust,
            revoked: Mutex::new(HashMap::new()),
            started: Instant::now(),
        }))
    }

    pub fn servers(&self) -> Arc<Servers> {
        self.servers.read().unwrap().clone()
    }

    pub fn cookie_name(&self) -> &'static str {
        if self.cfg.secure_cookies {
            "__Host-postern"
        } else {
            "postern"
        }
    }

    pub fn session_cookie(&self, value: &str, max_age: u64) -> String {
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
            self.cookie_name(),
            value,
            max_age,
            if self.cfg.secure_cookies {
                "; Secure"
            } else {
                ""
            }
        )
    }

    pub fn backend(
        &self,
        server: &ServerCfg,
        email: &str,
        pass: &str,
        key: &str,
    ) -> Box<dyn Backend> {
        let user = match server.username {
            UsernameStyle::Email => email.to_string(),
            UsernameStyle::Local => email.split('@').next().unwrap_or(email).to_string(),
        };
        match server.protocol {
            Protocol::Imap => Box::new(imap::ImapBackend {
                cfg: server.clone(),
                user,
                pass: pass.to_string(),
                key: key.to_string(),
                pool: self.imap_pool.clone(),
            }),
            Protocol::Jmap => Box::new(jmap::JmapBackend {
                cfg: server.clone(),
                user,
                pass: pass.to_string(),
                key: key.to_string(),
                sessions: self.jmap_sessions.clone(),
                http: self.http.clone(),
            }),
        }
    }

    /// Housekeeping, run once a minute.
    pub fn sweep(&self) {
        self.imap_pool.sweep();
        self.jmap_sessions.sweep();
        self.raw_cache.sweep();
        self.limiter.sweep();
        let now = seal::unix_now();
        self.revoked.lock().unwrap().retain(|_, exp| *exp > now);
    }

    pub fn revoke(&self, sid: &str, exp: u64) {
        self.revoked.lock().unwrap().insert(sid.to_string(), exp);
    }
}

pub fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

pub fn session_key(sid: &str, server: &str) -> String {
    let mut h = Sha256::new();
    h.update(sid.as_bytes());
    h.update(b"|");
    h.update(server.as_bytes());
    seal::hex(&h.finalize()[..16])
}

/// A signed-in request: the unsealed session plus the server it belongs to.
pub struct Auth {
    pub data: SessionData,
    pub server: ServerCfg,
    pub key: String,
}

impl Auth {
    pub fn backend(&self, st: &AppState) -> Box<dyn Backend> {
        st.backend(&self.server, &self.data.email, &self.data.pass, &self.key)
    }
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self> {
        let sealed = cookie(&parts.headers, st.cookie_name()).ok_or(Error::Unauthorized)?;
        let data: SessionData = st
            .sealer
            .open(SESSION_CONTEXT, sealed)
            .ok_or(Error::Unauthorized)?;
        if data.exp <= seal::unix_now() || st.revoked.lock().unwrap().contains_key(&data.sid) {
            return Err(Error::Unauthorized);
        }
        // A server that was removed or disabled, or a domain that no longer
        // maps to it, ends the session.
        let servers = st.servers();
        let server = servers
            .for_email(&data.email)
            .filter(|s| s.id == data.server)
            .cloned()
            .ok_or(Error::Unauthorized)?;
        let key = session_key(&data.sid, &data.server);
        Ok(Auth { data, server, key })
    }
}

/// The address a request came from, honouring the proxy header only when configured.
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self> {
        if st.cfg.trust_proxy {
            // The last entry is the one our own proxy appended.
            if let Some(ip) = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .and_then(|v| v.trim().parse().ok())
            {
                return Ok(ClientIp(ip));
            }
        }
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        Ok(ClientIp(peer))
    }
}

// ---- Sign-in rate limit ----------------------------------------------------

const WINDOW: Duration = Duration::from_secs(600);
const MAX_FAILURES: u32 = 10;

#[derive(Default)]
pub struct Limiter {
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

impl Limiter {
    pub fn allowed(&self, who: &str) -> bool {
        match self.failures.lock().unwrap().get(who) {
            Some((n, since)) => *n < MAX_FAILURES || since.elapsed() > WINDOW,
            None => true,
        }
    }
    pub fn failed(&self, who: &str) {
        let mut map = self.failures.lock().unwrap();
        let e = map.entry(who.to_string()).or_insert((0, Instant::now()));
        if e.1.elapsed() > WINDOW {
            *e = (0, Instant::now());
        }
        e.0 += 1;
    }
    pub fn succeeded(&self, who: &str) {
        self.failures.lock().unwrap().remove(who);
    }
    pub fn sweep(&self) {
        self.failures
            .lock()
            .unwrap()
            .retain(|_, (_, since)| since.elapsed() <= WINDOW);
    }
}

// ---- Short-lived message cache -----------------------------------------------

const RAW_TTL: Duration = Duration::from_secs(120);
const RAW_BUDGET: usize = 48 * 1024 * 1024;
const RAW_MAX_ITEM: usize = 16 * 1024 * 1024;

/// Keeps the last few opened messages in memory for two minutes, so that
/// showing a message, its HTML and its inline images costs one fetch, not five.
#[derive(Default)]
pub struct RawCache {
    items: Mutex<Vec<(String, Bytes, Instant)>>,
}

impl RawCache {
    /// Reading an entry keeps it for another two minutes.
    pub fn get(&self, key: &str) -> Option<Bytes> {
        let mut items = self.items.lock().unwrap();
        items
            .iter_mut()
            .find(|(k, _, t)| k == key && t.elapsed() < RAW_TTL)
            .map(|(_, b, t)| {
                *t = Instant::now();
                b.clone()
            })
    }
    pub fn put(&self, key: String, data: Bytes) {
        if data.len() > RAW_MAX_ITEM {
            return;
        }
        let mut items = self.items.lock().unwrap();
        items.retain(|(k, _, t)| *k != key && t.elapsed() < RAW_TTL);
        items.push((key, data, Instant::now()));
        let mut total: usize = items.iter().map(|i| i.1.len()).sum();
        while total > RAW_BUDGET && !items.is_empty() {
            total -= items.remove(0).1.len();
        }
    }
    pub fn drop_prefix(&self, prefix: &str) {
        self.items
            .lock()
            .unwrap()
            .retain(|(k, _, _)| !k.starts_with(prefix));
    }
    pub fn sweep(&self) {
        self.items
            .lock()
            .unwrap()
            .retain(|(_, _, t)| t.elapsed() < RAW_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_lookup() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "a=1; postern=abc.def; b=2".parse().unwrap());
        assert_eq!(cookie(&h, "postern"), Some("abc.def"));
        assert_eq!(cookie(&h, "ostern"), None);
        assert_eq!(cookie(&h, "missing"), None);
    }

    #[test]
    fn limiter_blocks_after_failures() {
        let l = Limiter::default();
        for _ in 0..MAX_FAILURES {
            assert!(l.allowed("x"));
            l.failed("x");
        }
        assert!(!l.allowed("x"));
        assert!(l.allowed("y"));
        l.succeeded("x");
        assert!(l.allowed("x"));
    }

    #[test]
    fn raw_cache_respects_budget() {
        let c = RawCache::default();
        c.put("a".into(), Bytes::from(vec![0u8; 10]));
        assert_eq!(c.get("a").unwrap().len(), 10);
        c.put("big".into(), Bytes::from(vec![0u8; RAW_MAX_ITEM + 1]));
        assert!(c.get("big").is_none());
        for i in 0..5 {
            c.put(format!("k{i}"), Bytes::from(vec![0u8; RAW_MAX_ITEM]));
        }
        assert!(c.get("a").is_none());
        assert!(c.get("k4").is_some());
        c.drop_prefix("k");
        assert!(c.get("k4").is_none());
    }

    #[test]
    fn session_keys_differ() {
        assert_ne!(session_key("a", "s"), session_key("b", "s"));
        assert_ne!(session_key("a", "s"), session_key("a", "t"));
    }
}
