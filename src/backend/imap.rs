//! IMAP for reading and filing, SMTP for sending.
//!
//! Each signed-in session keeps at most one IMAP connection, reused for a few
//! minutes. Message identifiers are IMAP UIDs and are parsed as numbers before
//! they go anywhere near a command.

use super::{
    Backend, Flag, MailboxInfo, Outgoing, Page, Summary, role_from_name, tls_config,
    valid_folder_name,
};
use crate::{
    config::{Security, ServerCfg},
    error::{Error, Result},
    message,
};
use async_imap::{Client, Session, types::NameAttribute};
use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{Mutex, OwnedMutexGuard},
    time::timeout,
};
use tokio_rustls::{TlsConnector, rustls::pki_types::ServerName};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + Debug {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Debug> Io for T {}
type Stream = Box<dyn Io>;
type Sess = Session<Stream>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const OP_TIMEOUT: Duration = Duration::from_secs(90);
const IDLE_CLOSE: Duration = Duration::from_secs(240);
const NOOP_AFTER: Duration = Duration::from_secs(25);
const PREVIEW_BYTES: usize = 3072;

#[derive(Default)]
pub struct Slot {
    sess: Option<Sess>,
    used: Option<Instant>,
    can_move: bool,
    can_uid_expunge: bool,
}

/// Connections kept open between requests, one per signed-in session.
#[derive(Clone, Default)]
pub struct Pool {
    slots: Arc<StdMutex<HashMap<String, Arc<Mutex<Slot>>>>>,
}

impl Pool {
    fn slot(&self, key: &str) -> Arc<Mutex<Slot>> {
        self.slots
            .lock()
            .unwrap()
            .entry(key.to_string())
            .or_default()
            .clone()
    }

    pub fn forget(&self, key: &str) {
        self.slots.lock().unwrap().remove(key);
    }

    /// Closes connections that have not been used for a while.
    pub fn sweep(&self) {
        let mut slots = self.slots.lock().unwrap();
        slots.retain(|_, slot| match slot.try_lock() {
            Ok(mut s) => {
                let stale = s.used.map(|t| t.elapsed() > IDLE_CLOSE).unwrap_or(true);
                if stale {
                    s.sess = None;
                }
                !stale
            }
            Err(_) => true,
        });
    }
}

pub struct ImapBackend {
    pub cfg: ServerCfg,
    pub user: String,
    pub pass: String,
    pub key: String,
    pub pool: Pool,
}

fn uid_set(ids: &[String]) -> Result<String> {
    if ids.is_empty() || ids.len() > 2000 {
        return Err(Error::bad("between 1 and 2000 messages per request"));
    }
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let n: u32 = id.parse().map_err(|_| Error::bad("invalid message id"))?;
        if n == 0 {
            return Err(Error::bad("invalid message id"));
        }
        out.push(n.to_string());
    }
    Ok(out.join(","))
}

fn check_mailbox(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 1000 || name.chars().any(|c| c.is_control()) {
        return Err(Error::bad("invalid folder"));
    }
    Ok(())
}

fn flag_atom(f: Flag) -> &'static str {
    match f {
        Flag::Seen => "\\Seen",
        Flag::Flagged => "\\Flagged",
        Flag::Answered => "\\Answered",
        Flag::Draft => "\\Draft",
    }
}

/// Builds a SEARCH key for free text. Quoted strings carry the text; quotes
/// and backslashes are escaped and control characters dropped.
fn search_key(q: &str) -> String {
    let cleaned: String = q
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect::<String>()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let charset = if cleaned.is_ascii() {
        ""
    } else {
        "CHARSET UTF-8 "
    };
    format!(
        "{charset}OR OR OR SUBJECT \"{cleaned}\" FROM \"{cleaned}\" TO \"{cleaned}\" BODY \"{cleaned}\""
    )
}

async fn tcp(host: &str, port: u16) -> Result<TcpStream> {
    let s = timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| Error::Unreachable("connect timed out".into()))??;
    let _ = s.set_nodelay(true);
    Ok(s)
}

async fn tls(cfg: &ServerCfg, host: &str, stream: TcpStream) -> Result<Stream> {
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| Error::Unreachable("invalid server name".into()))?;
    let s = TlsConnector::from(tls_config(cfg.tls_insecure))
        .connect(name, stream)
        .await
        .map_err(|e| Error::Unreachable(format!("TLS: {e}")))?;
    Ok(Box::new(s))
}

impl ImapBackend {
    async fn connect(&self) -> Result<(Sess, bool, bool)> {
        let host = self.cfg.imap_host.as_str();
        let stream = tcp(host, self.cfg.imap_port).await?;
        let client = match self.cfg.imap_security {
            Security::Tls => {
                let mut c = Client::new(tls(&self.cfg, host, stream).await?);
                c.read_response().await?;
                c
            }
            Security::None => {
                let mut c = Client::new(Box::new(stream) as Stream);
                c.read_response().await?;
                c
            }
            Security::Starttls => {
                let mut c = Client::new(stream);
                c.read_response().await?;
                c.run_command_and_check_ok("STARTTLS", None).await?;
                Client::new(tls(&self.cfg, host, c.into_inner()).await?)
            }
        };
        let mut sess = match client.login(&self.user, &self.pass).await {
            Ok(s) => s,
            Err((async_imap::error::Error::No(_), _)) => return Err(Error::BadCredentials),
            Err((e, _)) => return Err(e.into()),
        };
        let caps = sess.capabilities().await?;
        Ok((sess, caps.has_str("MOVE"), caps.has_str("UIDPLUS")))
    }

    /// Hands out this session's connection, opening or reviving it as needed.
    async fn acquire(&self) -> Result<OwnedMutexGuard<Slot>> {
        let mut slot = self.pool.slot(&self.key).lock_owned().await;
        let idle = slot.used.map(|t| t.elapsed() > NOOP_AFTER).unwrap_or(true);
        if idle {
            let alive = match slot.sess.as_mut() {
                Some(sess) => matches!(
                    timeout(Duration::from_secs(8), sess.noop()).await,
                    Ok(Ok(()))
                ),
                None => false,
            };
            if !alive {
                slot.sess = None;
            }
        }
        if slot.sess.is_none() {
            let (sess, can_move, can_uid_expunge) =
                timeout(Duration::from_secs(30), self.connect())
                    .await
                    .map_err(|_| Error::Unreachable("sign-in timed out".into()))??;
            slot.sess = Some(sess);
            slot.can_move = can_move;
            slot.can_uid_expunge = can_uid_expunge;
        }
        slot.used = Some(Instant::now());
        Ok(slot)
    }
}

/// Runs one unit of IMAP work on the pooled connection. A failure or timeout
/// drops the connection, because its state is no longer known.
macro_rules! with_session {
    ($self:ident, |$s:ident, $slot:ident| $body:expr) => {{
        let mut guard = $self.acquire().await?;
        let $slot = (guard.can_move, guard.can_uid_expunge);
        let _ = &$slot;
        let result = {
            let $s = guard.sess.as_mut().expect("connected");
            match timeout(OP_TIMEOUT, async { $body }).await {
                Ok(r) => r,
                Err(_) => Err(Error::Unreachable("mail server timed out".into())),
            }
        };
        match &result {
            Err(Error::Unreachable(_)) | Err(Error::Internal(_)) => guard.sess = None,
            _ => guard.used = Some(Instant::now()),
        }
        result
    }};
}

fn role_of(attrs: &[NameAttribute<'_>], display: &str, raw: &str) -> Option<String> {
    for a in attrs {
        let r = match a {
            NameAttribute::Sent => "sent",
            NameAttribute::Drafts => "drafts",
            NameAttribute::Trash => "trash",
            NameAttribute::Junk => "junk",
            NameAttribute::Archive => "archive",
            _ => continue,
        };
        return Some(r.to_string());
    }
    if raw.eq_ignore_ascii_case("INBOX") {
        return Some("inbox".into());
    }
    role_from_name(display)
        .filter(|r| *r != "inbox")
        .map(String::from)
}

async fn expunge(s: &mut Sess, set: &str, uid_expunge: bool) -> Result<()> {
    if uid_expunge {
        let _: Vec<_> = s.uid_expunge(set).await?.try_collect().await?;
    } else {
        let _: Vec<_> = s.expunge().await?.try_collect().await?;
    }
    Ok(())
}

/// APPEND that tolerates what real servers do: untagged responses (a new
/// message count, a flag change) may arrive before the "go ahead" for the
/// literal. The library's own `append` treats those as a failure and leaves
/// the connection in a broken state, so the exchange is done by hand here.
async fn append_message(s: &mut Sess, mailbox: &str, flags: &str, raw: &[u8]) -> Result<()> {
    use async_imap::imap_proto::{Response, Status};
    use tokio::io::AsyncWriteExt;
    let quoted = format!("\"{}\"", mailbox.replace('\\', "\\\\").replace('"', "\\\""));
    let id = s
        .run_command(format!("APPEND {quoted} {flags} {{{}}}", raw.len()))
        .await?;
    let lost = || Error::Unreachable("connection lost during APPEND".into());
    loop {
        let resp = s.read_response().await?.ok_or_else(lost)?;
        match resp.parsed() {
            Response::Continue(_) => break,
            Response::Done { tag, .. } if *tag == id => {
                // Refused before the literal was requested: no such folder, over quota, too large.
                return Err(Error::Upstream(
                    "the server refused to store the message".into(),
                ));
            }
            _ => {}
        }
    }
    let io = s.get_mut();
    io.write_all(raw).await?;
    io.write_all(b"\r\n").await?;
    io.flush().await?;
    loop {
        let resp = s.read_response().await?.ok_or_else(lost)?;
        if let Response::Done { tag, status, .. } = resp.parsed() {
            if *tag == id {
                return match status {
                    Status::Ok => Ok(()),
                    _ => Err(Error::Upstream(
                        "the server refused to store the message".into(),
                    )),
                };
            }
        }
    }
}

async fn delimiter(s: &mut Sess) -> Result<String> {
    let names: Vec<_> = s.list(Some(""), Some("\"\"")).await?.try_collect().await?;
    Ok(names
        .first()
        .and_then(|n| n.delimiter())
        .unwrap_or("/")
        .to_string())
}

#[async_trait]
impl Backend for ImapBackend {
    async fn verify(&self) -> Result<()> {
        self.acquire().await.map(|_| ())
    }

    async fn mailboxes(&self) -> Result<Vec<MailboxInfo>> {
        with_session!(self, |s, _caps| {
            let names: Vec<_> = s.list(Some(""), Some("*")).await?.try_collect().await?;
            let mut out = Vec::with_capacity(names.len());
            let mut seen_roles = std::collections::HashSet::new();
            for n in &names {
                let raw = n.name().to_string();
                let delim = n.delimiter().unwrap_or("/").to_string();
                let display_path = utf7_imap::decode_utf7_imap(raw.clone());
                let (parent, leaf) = match raw.rsplit_once(delim.as_str()) {
                    Some((p, _)) if !p.is_empty() => (
                        Some(p.to_string()),
                        display_path
                            .rsplit_once(delim.as_str())
                            .map(|x| x.1.to_string())
                            .unwrap_or_else(|| display_path.clone()),
                    ),
                    _ => (None, display_path.clone()),
                };
                let selectable = !n
                    .attributes()
                    .iter()
                    .any(|a| matches!(a, NameAttribute::NoSelect));
                let mut role = role_of(n.attributes(), &leaf, &raw);
                // A role belongs to one folder only; top-level folders win.
                if let Some(r) = &role {
                    if (parent.is_some()
                        && r != "inbox"
                        && !n.attributes().iter().any(|a| {
                            matches!(
                                a,
                                NameAttribute::Sent
                                    | NameAttribute::Drafts
                                    | NameAttribute::Trash
                                    | NameAttribute::Junk
                                    | NameAttribute::Archive
                            )
                        }))
                        || !seen_roles.insert(r.clone())
                    {
                        role = None;
                    }
                }
                out.push(MailboxInfo {
                    id: raw,
                    name: if leaf.eq_ignore_ascii_case("INBOX") && parent.is_none() {
                        "Inbox".into()
                    } else {
                        leaf
                    },
                    parent,
                    role,
                    total: 0,
                    unread: 0,
                    selectable,
                });
            }
            for mb in out.iter_mut().filter(|m| m.selectable) {
                if let Ok(st) = s.status(&mb.id, "(MESSAGES UNSEEN)").await {
                    mb.total = st.exists;
                    mb.unread = st.unseen.unwrap_or(0);
                }
            }
            Ok(out)
        })
    }

    async fn list(
        &self,
        mailbox: &str,
        offset: usize,
        limit: usize,
        query: Option<&str>,
    ) -> Result<Page> {
        check_mailbox(mailbox)?;
        let key = match query.map(str::trim).filter(|q| !q.is_empty()) {
            Some(q) => search_key(q),
            None => "ALL".to_string(),
        };
        with_session!(self, |s, _caps| {
            s.select(mailbox).await?;
            let mut uids: Vec<u32> = s.uid_search(&key).await?.into_iter().collect();
            uids.sort_unstable_by(|a, b| b.cmp(a));
            let total = uids.len();
            let page: Vec<u32> = uids.into_iter().skip(offset).take(limit).collect();
            let mut items = Vec::with_capacity(page.len());
            if !page.is_empty() {
                let set = page
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let query = format!(
                    "(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER] BODY.PEEK[TEXT]<0.{PREVIEW_BYTES}>)"
                );
                let fetched: Vec<_> = s.uid_fetch(&set, &query).await?.try_collect().await?;
                let mut by_uid: HashMap<u32, Summary> = HashMap::new();
                for f in &fetched {
                    let Some(uid) = f.uid else { continue };
                    let mut buf = f.header().unwrap_or_default().to_vec();
                    if !buf.ends_with(b"\r\n\r\n") {
                        buf.extend_from_slice(b"\r\n");
                    }
                    buf.extend_from_slice(f.text().unwrap_or_default());
                    let mut sum = message::summarize(&buf);
                    sum.id = uid.to_string();
                    sum.size = f.size.unwrap_or(0) as u64;
                    if let Some(d) = f.internal_date() {
                        sum.date = Some(d.to_rfc3339());
                    }
                    for flag in f.flags() {
                        use async_imap::types::Flag as F;
                        match flag {
                            F::Seen => sum.seen = true,
                            F::Flagged => sum.flagged = true,
                            F::Answered => sum.answered = true,
                            F::Draft => sum.draft = true,
                            _ => {}
                        }
                    }
                    by_uid.insert(uid, sum);
                }
                items.extend(page.iter().filter_map(|u| by_uid.remove(u)));
            }
            Ok(Page {
                total,
                offset,
                items,
            })
        })
    }

    async fn raw(&self, mailbox: &str, id: &str) -> Result<Bytes> {
        check_mailbox(mailbox)?;
        let set = uid_set(&[id.to_string()])?;
        with_session!(self, |s, _caps| {
            s.select(mailbox).await?;
            let fetched: Vec<_> = s
                .uid_fetch(&set, "(UID BODY.PEEK[])")
                .await?
                .try_collect()
                .await?;
            fetched
                .iter()
                .find_map(|f| f.body().map(Bytes::copy_from_slice))
                .ok_or(Error::NotFound)
        })
    }

    async fn set_flag(&self, mailbox: &str, ids: &[String], flag: Flag, on: bool) -> Result<()> {
        check_mailbox(mailbox)?;
        let set = uid_set(ids)?;
        let cmd = format!(
            "{}FLAGS.SILENT ({})",
            if on { "+" } else { "-" },
            flag_atom(flag)
        );
        with_session!(self, |s, _caps| {
            s.select(mailbox).await?;
            let _: Vec<_> = s.uid_store(&set, &cmd).await?.try_collect().await?;
            Ok(())
        })
    }

    async fn move_to(&self, mailbox: &str, ids: &[String], dest: &str) -> Result<()> {
        check_mailbox(mailbox)?;
        check_mailbox(dest)?;
        let set = uid_set(ids)?;
        with_session!(self, |s, caps| {
            s.select(mailbox).await?;
            if caps.0 {
                s.uid_mv(&set, dest).await?;
            } else {
                s.uid_copy(&set, dest).await?;
                let _: Vec<_> = s
                    .uid_store(&set, "+FLAGS.SILENT (\\Deleted)")
                    .await?
                    .try_collect()
                    .await?;
                expunge(s, &set, caps.1).await?;
            }
            Ok(())
        })
    }

    async fn destroy(&self, mailbox: &str, ids: &[String]) -> Result<()> {
        check_mailbox(mailbox)?;
        let set = uid_set(ids)?;
        with_session!(self, |s, caps| {
            s.select(mailbox).await?;
            let _: Vec<_> = s
                .uid_store(&set, "+FLAGS.SILENT (\\Deleted)")
                .await?
                .try_collect()
                .await?;
            expunge(s, &set, caps.1).await
        })
    }

    async fn append(&self, mailbox: &str, raw: &[u8], flags: &[Flag]) -> Result<()> {
        check_mailbox(mailbox)?;
        let flags = format!(
            "({})",
            flags
                .iter()
                .map(|f| flag_atom(*f))
                .collect::<Vec<_>>()
                .join(" ")
        );
        with_session!(self, |s, _caps| {
            append_message(s, mailbox, &flags, raw).await
        })
    }

    async fn send(&self, out: &Outgoing) -> Result<()> {
        smtp_send(&self.cfg, &self.user, &self.pass, out).await?;
        if self.cfg.save_sent {
            if let Some(sent) = &out.sent_mailbox {
                // The message is already on its way; a failed copy must not look like a failed send.
                if let Err(e) = self.append(sent, &out.copy, &[Flag::Seen]).await {
                    tracing::warn!(error = %e, "sent, but could not store the copy");
                }
            }
        }
        Ok(())
    }

    async fn create_mailbox(&self, parent: Option<&str>, name: &str) -> Result<()> {
        if !valid_folder_name(name) {
            return Err(Error::bad("invalid folder name"));
        }
        if let Some(p) = parent {
            check_mailbox(p)?;
        }
        with_session!(self, |s, _caps| {
            let delim = delimiter(s).await?;
            if name.contains(delim.as_str()) {
                return Err(Error::bad(format!(
                    "folder names cannot contain \"{delim}\""
                )));
            }
            let leaf = utf7_imap::encode_utf7_imap(name.trim().to_string());
            let full = match parent {
                Some(p) => format!("{p}{delim}{leaf}"),
                None => leaf,
            };
            s.create(&full).await?;
            let _ = s.subscribe(&full).await;
            Ok(())
        })
    }

    async fn rename_mailbox(&self, id: &str, name: &str) -> Result<()> {
        check_mailbox(id)?;
        if !valid_folder_name(name) || id.eq_ignore_ascii_case("INBOX") {
            return Err(Error::bad("invalid folder name"));
        }
        with_session!(self, |s, _caps| {
            let delim = delimiter(s).await?;
            if name.contains(delim.as_str()) {
                return Err(Error::bad(format!(
                    "folder names cannot contain \"{delim}\""
                )));
            }
            let leaf = utf7_imap::encode_utf7_imap(name.trim().to_string());
            let full = match id.rsplit_once(delim.as_str()) {
                Some((p, _)) => format!("{p}{delim}{leaf}"),
                None => leaf,
            };
            s.rename(id, &full).await?;
            let _ = s.unsubscribe(id).await;
            let _ = s.subscribe(&full).await;
            Ok(())
        })
    }

    async fn delete_mailbox(&self, id: &str) -> Result<()> {
        check_mailbox(id)?;
        if id.eq_ignore_ascii_case("INBOX") {
            return Err(Error::bad("the inbox cannot be deleted"));
        }
        with_session!(self, |s, _caps| {
            // Leave the folder first in case it is the selected one.
            let _ = s.examine("INBOX").await;
            let _ = s.unsubscribe(id).await;
            s.delete(id).await?;
            Ok(())
        })
    }
}

/// Connects and reads the greeting without signing in. Used by the admin console's test button.
pub async fn probe(cfg: &ServerCfg) -> Result<String> {
    let host = cfg.imap_host.as_str();
    let stream = tcp(host, cfg.imap_port).await?;
    let gone = || Error::Unreachable("no greeting".into());
    match cfg.imap_security {
        Security::Tls => {
            let mut c = Client::new(tls(cfg, host, stream).await?);
            c.read_response().await?.ok_or_else(gone)?;
            Ok("TLS handshake and greeting OK".into())
        }
        Security::None => {
            let mut c = Client::new(Box::new(stream) as Stream);
            c.read_response().await?.ok_or_else(gone)?;
            Ok("greeting OK (unencrypted)".into())
        }
        Security::Starttls => {
            let mut c = Client::new(stream);
            c.read_response().await?.ok_or_else(gone)?;
            c.run_command_and_check_ok("STARTTLS", None).await?;
            tls(cfg, host, c.into_inner()).await?;
            Ok("greeting and STARTTLS OK".into())
        }
    }
}

pub async fn smtp_send(cfg: &ServerCfg, user: &str, pass: &str, out: &Outgoing) -> Result<()> {
    use mail_send::{SmtpClientBuilder, smtp::message::Message};
    if out.recipients.is_empty() {
        return Err(Error::bad("no recipients"));
    }
    let connector = TlsConnector::from(tls_config(cfg.tls_insecure));
    let builder =
        SmtpClientBuilder::new_with_tls_connector(cfg.smtp_host.clone(), cfg.smtp_port, connector)
            .implicit_tls(cfg.smtp_security == Security::Tls)
            .credentials((user.to_string(), pass.to_string()))
            .timeout(Duration::from_secs(60));
    let msg = Message::new(
        out.from.clone(),
        out.recipients.clone(),
        out.wire.as_slice(),
    );
    let map = |e: mail_send::Error| match e {
        mail_send::Error::Io(e) => Error::Unreachable(e.to_string()),
        mail_send::Error::Timeout => Error::Unreachable("SMTP timed out".into()),
        mail_send::Error::AuthenticationFailed(_) => {
            Error::Upstream("the SMTP server did not accept the sign-in".into())
        }
        other => Error::upstream(format!("SMTP: {other}")),
    };
    if cfg.smtp_security == Security::None {
        let mut c = builder.connect_plain().await.map_err(map)?;
        c.send(msg).await.map_err(map)?;
        let _ = c.quit().await;
    } else {
        let mut c = builder.connect().await.map_err(map)?;
        c.send(msg).await.map_err(map)?;
        let _ = c.quit().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_sets_only_take_numbers() {
        assert_eq!(uid_set(&["1".into(), "42".into()]).unwrap(), "1,42");
        assert!(uid_set(&["1 2".into()]).is_err());
        assert!(uid_set(&["1:*".into()]).is_err());
        assert!(uid_set(&["0".into()]).is_err());
        assert!(uid_set(&["1\r\nA1 DELETE x".into()]).is_err());
        assert!(uid_set(&[]).is_err());
    }

    #[test]
    fn search_keys_are_escaped() {
        let k = search_key("in\"voice\\ \r\nA1 LOGOUT");
        assert!(!k.contains('\r') && !k.contains('\n'));
        assert!(k.contains("in\\\"voice\\\\"));
        assert!(search_key("gr\u{fc}n").starts_with("CHARSET UTF-8 "));
        assert!(search_key("plain").starts_with("OR OR OR"));
    }

    #[test]
    fn mailbox_names_reject_control_characters() {
        assert!(check_mailbox("INBOX").is_ok());
        assert!(check_mailbox("a\r\nb").is_err());
        assert!(check_mailbox("").is_err());
    }
}
