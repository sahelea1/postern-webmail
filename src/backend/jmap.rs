//! JMAP (RFC 8620 core, RFC 8621 mail) over HTTPS with Basic authentication.
//!
//! Every request goes to the origin the admin configured. URLs handed out by
//! the server's session object are re-pinned to that origin, and redirects
//! are followed by hand, so a mail server cannot steer requests elsewhere.

use super::{Backend, Flag, MailboxInfo, Outgoing, Page, Summary, valid_folder_name};
use crate::{
    backend::Addr,
    config::ServerCfg,
    error::{Error, Result},
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use bytes::Bytes;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{StatusCode, header};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const SESSION_TTL: Duration = Duration::from_secs(600);
const CORE: &str = "urn:ietf:params:jmap:core";
const MAIL: &str = "urn:ietf:params:jmap:mail";
const SUBMISSION: &str = "urn:ietf:params:jmap:submission";

#[derive(Clone, Debug)]
pub struct JSession {
    api_url: String,
    upload_url: String,
    download_url: String,
    account_id: String,
    submission: bool,
}

#[derive(Clone, Default)]
pub struct Sessions {
    map: Arc<Mutex<HashMap<String, (JSession, Instant)>>>,
}

impl Sessions {
    pub fn forget(&self, key: &str) {
        self.map.lock().unwrap().remove(key);
    }
    pub fn sweep(&self) {
        self.map
            .lock()
            .unwrap()
            .retain(|_, (_, t)| t.elapsed() < SESSION_TTL);
    }
}

#[derive(Clone)]
pub struct HttpClients {
    strict: reqwest::Client,
    lax: reqwest::Client,
}

impl HttpClients {
    pub fn new() -> Self {
        let build = |insecure: bool| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(12))
                .timeout(Duration::from_secs(120))
                .user_agent(concat!("Postern/", env!("CARGO_PKG_VERSION")))
                .danger_accept_invalid_certs(insecure)
                .build()
                .expect("HTTP client")
        };
        HttpClients {
            strict: build(false),
            lax: build(true),
        }
    }
}

pub struct JmapBackend {
    pub cfg: ServerCfg,
    pub user: String,
    pub pass: String,
    pub key: String,
    pub sessions: Sessions,
    pub http: HttpClients,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 255
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn check_id(id: &str) -> Result<()> {
    if valid_id(id) {
        Ok(())
    } else {
        Err(Error::bad("invalid identifier"))
    }
}

fn check_ids(ids: &[String]) -> Result<()> {
    if ids.is_empty() || ids.len() > 500 {
        return Err(Error::bad("between 1 and 500 messages per request"));
    }
    ids.iter().try_for_each(|i| check_id(i))
}

/// `scheme://host[:port]` of the configured server.
fn origin_of(base: &str) -> Result<String> {
    let u = reqwest::Url::parse(base).map_err(|_| Error::Internal("jmap_url".into()))?;
    Ok(u.origin().ascii_serialization())
}

/// Keeps the path and query of `url` but forces the configured origin.
/// Works on strings because JMAP URL templates contain `{braces}`.
fn pin(origin: &str, url: &str) -> Result<String> {
    let path = if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        }
    } else if url.starts_with('/') && !url.starts_with("//") {
        url
    } else {
        return Err(Error::Upstream(
            "the mail server sent an unusable URL".into(),
        ));
    };
    if path.chars().any(|c| c.is_control() || c == ' ') {
        return Err(Error::Upstream(
            "the mail server sent an unusable URL".into(),
        ));
    }
    Ok(format!("{origin}{path}"))
}

fn enc(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

fn keyword(f: Flag) -> &'static str {
    match f {
        Flag::Seen => "$seen",
        Flag::Flagged => "$flagged",
        Flag::Answered => "$answered",
        Flag::Draft => "$draft",
    }
}

fn addr_list(v: &Value) -> Vec<Addr> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    Some(Addr {
                        email: x.get("email")?.as_str()?.to_string(),
                        name: x
                            .get("name")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                            .filter(|n| !n.is_empty()),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn has_kw(email: &Value, kw: &str) -> bool {
    email
        .get("keywords")
        .and_then(|k| k.get(kw))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Fails if a `/set` or `/import` response reports a rejected item.
fn check_set(args: &Value) -> Result<()> {
    for field in ["notCreated", "notUpdated", "notDestroyed"] {
        if let Some(obj) = args.get(field).and_then(Value::as_object) {
            if let Some((_, err)) = obj.iter().next() {
                let kind = err.get("type").and_then(Value::as_str).unwrap_or("error");
                let desc = err.get("description").and_then(Value::as_str).unwrap_or("");
                return Err(Error::upstream(format!("{kind} {desc}")));
            }
        }
    }
    Ok(())
}

impl JmapBackend {
    fn client(&self) -> &reqwest::Client {
        if self.cfg.tls_insecure {
            &self.http.lax
        } else {
            &self.http.strict
        }
    }

    fn auth(&self) -> String {
        format!(
            "Basic {}",
            B64.encode(format!("{}:{}", self.user, self.pass))
        )
    }

    /// GET that follows redirects itself, always staying on the configured origin.
    async fn get_pinned(&self, origin: &str, start: String) -> Result<reqwest::Response> {
        let mut url = start;
        for _ in 0..4 {
            let resp = self
                .client()
                .get(&url)
                .header(header::AUTHORIZATION, self.auth())
                .header(header::ACCEPT, "application/json")
                .send()
                .await?;
            if resp.status().is_redirection() {
                let loc = resp
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| Error::Upstream("redirect without a target".into()))?;
                url = pin(origin, loc)?;
                continue;
            }
            return Ok(resp);
        }
        Err(Error::Upstream("too many redirects".into()))
    }

    async fn fetch_session(&self) -> Result<JSession> {
        let origin = origin_of(&self.cfg.jmap_url)?;
        let base = reqwest::Url::parse(&self.cfg.jmap_url)
            .map_err(|_| Error::Internal("jmap_url".into()))?;
        let start = if base.path() == "/" || base.path().is_empty() {
            format!("{origin}/.well-known/jmap")
        } else {
            self.cfg.jmap_url.clone()
        };
        let resp = self.get_pinned(&origin, start).await?;
        match resp.status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => return Err(Error::BadCredentials),
            s if !s.is_success() => {
                return Err(Error::upstream(format!("session request returned {s}")));
            }
            _ => {}
        }
        let v: Value = resp.json().await?;
        let account_id = v
            .pointer(&format!(
                "/primaryAccounts/{}",
                MAIL.replace('~', "~0").replace('/', "~1")
            ))
            .and_then(Value::as_str)
            .or_else(|| {
                v.get("accounts")
                    .and_then(Value::as_object)
                    .and_then(|a| a.keys().next().map(String::as_str))
            })
            .ok_or_else(|| Error::Upstream("the server offers no mail account".into()))?
            .to_string();
        check_id(&account_id).map_err(|_| Error::Upstream("unusable account id".into()))?;
        let url = |name: &str| -> Result<String> {
            pin(
                &origin,
                v.get(name)
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::Upstream(format!("session lacks {name}")))?,
            )
        };
        Ok(JSession {
            api_url: url("apiUrl")?,
            upload_url: url("uploadUrl")?,
            download_url: url("downloadUrl")?,
            submission: v
                .get("capabilities")
                .map(|c| c.get(SUBMISSION).is_some())
                .unwrap_or(false),
            account_id,
        })
    }

    async fn session(&self) -> Result<JSession> {
        if let Some((s, t)) = self.sessions.map.lock().unwrap().get(&self.key) {
            if t.elapsed() < SESSION_TTL {
                return Ok(s.clone());
            }
        }
        let s = self.fetch_session().await?;
        self.sessions
            .map
            .lock()
            .unwrap()
            .insert(self.key.clone(), (s.clone(), Instant::now()));
        Ok(s)
    }

    /// Sends method calls and returns each response's arguments, in order.
    async fn call(&self, s: &JSession, calls: Value) -> Result<Vec<Value>> {
        let mut using = vec![CORE, MAIL];
        if s.submission {
            using.push(SUBMISSION);
        }
        let resp = self
            .client()
            .post(&s.api_url)
            .header(header::AUTHORIZATION, self.auth())
            .json(&json!({ "using": using, "methodCalls": calls }))
            .send()
            .await?;
        match resp.status() {
            StatusCode::UNAUTHORIZED => {
                self.sessions.forget(&self.key);
                return Err(Error::Unauthorized);
            }
            st if !st.is_success() => {
                self.sessions.forget(&self.key);
                return Err(Error::upstream(format!("request returned {st}")));
            }
            _ => {}
        }
        let v: Value = resp.json().await?;
        let list = v
            .get("methodResponses")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Upstream("malformed response".into()))?;
        let mut out = Vec::with_capacity(list.len());
        for r in list {
            let name = r.get(0).and_then(Value::as_str).unwrap_or("");
            let args = r.get(1).cloned().unwrap_or(Value::Null);
            if name == "error" {
                let kind = args.get("type").and_then(Value::as_str).unwrap_or("error");
                let desc = args
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                return Err(Error::upstream(format!("{kind} {desc}")));
            }
            out.push(args);
        }
        Ok(out)
    }

    async fn upload(&self, s: &JSession, raw: &[u8]) -> Result<String> {
        let url = s.upload_url.replace("{accountId}", &enc(&s.account_id));
        let resp = self
            .client()
            .post(&url)
            .header(header::AUTHORIZATION, self.auth())
            .header(header::CONTENT_TYPE, "message/rfc822")
            .body(raw.to_vec())
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Error::upstream(format!(
                "upload returned {}",
                resp.status()
            )));
        }
        let v: Value = resp.json().await?;
        v.get("blobId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Error::Upstream("upload returned no blob id".into()))
    }

    /// Stores a raw message and returns its new email id.
    async fn import(
        &self,
        s: &JSession,
        raw: &[u8],
        mailbox: &str,
        flags: &[Flag],
    ) -> Result<String> {
        let blob = self.upload(s, raw).await?;
        let keywords: serde_json::Map<String, Value> = flags
            .iter()
            .map(|f| (keyword(*f).to_string(), Value::Bool(true)))
            .collect();
        let r = self
            .call(
                s,
                json!([["Email/import", {
                    "accountId": s.account_id,
                    "emails": { "m": { "blobId": blob, "mailboxIds": { mailbox: true }, "keywords": keywords } }
                }, "0"]]),
            )
            .await?;
        let args = r
            .first()
            .ok_or_else(|| Error::Upstream("empty response".into()))?;
        check_set(args)?;
        args.pointer("/created/m/id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Error::Upstream("import returned no id".into()))
    }

    async fn email_set(&self, s: &JSession, body: Value) -> Result<()> {
        let mut args = body;
        args["accountId"] = json!(s.account_id);
        let r = self.call(s, json!([["Email/set", args, "0"]])).await?;
        check_set(r.first().unwrap_or(&Value::Null))
    }

    async fn mailbox_set(&self, s: &JSession, body: Value) -> Result<()> {
        let mut args = body;
        args["accountId"] = json!(s.account_id);
        let r = self.call(s, json!([["Mailbox/set", args, "0"]])).await?;
        check_set(r.first().unwrap_or(&Value::Null))
    }
}

#[async_trait]
impl Backend for JmapBackend {
    async fn verify(&self) -> Result<()> {
        self.sessions.forget(&self.key);
        self.session().await.map(|_| ())
    }

    async fn mailboxes(&self) -> Result<Vec<MailboxInfo>> {
        let s = self.session().await?;
        let r = self
            .call(
                &s,
                json!([["Mailbox/get", {
                    "accountId": s.account_id, "ids": null,
                    "properties": ["id", "name", "parentId", "role", "totalEmails", "unreadEmails", "sortOrder"]
                }, "0"]]),
            )
            .await?;
        let mut list: Vec<(u64, MailboxInfo)> = r
            .first()
            .and_then(|a| a.get("list"))
            .and_then(Value::as_array)
            .map(|l| {
                l.iter()
                    .filter_map(|m| {
                        let id = m.get("id")?.as_str()?.to_string();
                        if !valid_id(&id) {
                            return None;
                        }
                        let role = m
                            .get("role")
                            .and_then(Value::as_str)
                            .map(str::to_ascii_lowercase)
                            .filter(|r| {
                                matches!(
                                    r.as_str(),
                                    "inbox" | "drafts" | "sent" | "trash" | "junk" | "archive"
                                )
                            });
                        Some((
                            m.get("sortOrder").and_then(Value::as_u64).unwrap_or(0),
                            MailboxInfo {
                                id,
                                name: m
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                parent: m
                                    .get("parentId")
                                    .and_then(Value::as_str)
                                    .map(str::to_string),
                                role,
                                total: m.get("totalEmails").and_then(Value::as_u64).unwrap_or(0)
                                    as u32,
                                unread: m.get("unreadEmails").and_then(Value::as_u64).unwrap_or(0)
                                    as u32,
                                selectable: true,
                            },
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        list.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.name.to_lowercase().cmp(&b.1.name.to_lowercase()))
        });
        Ok(list.into_iter().map(|x| x.1).collect())
    }

    async fn list(
        &self,
        mailbox: &str,
        offset: usize,
        limit: usize,
        query: Option<&str>,
    ) -> Result<Page> {
        check_id(mailbox)?;
        let s = self.session().await?;
        let mut filter = json!({ "inMailbox": mailbox });
        if let Some(q) = query.map(str::trim).filter(|q| !q.is_empty()) {
            filter["text"] = json!(
                q.chars()
                    .filter(|c| !c.is_control())
                    .take(200)
                    .collect::<String>()
            );
        }
        let r = self
            .call(
                &s,
                json!([
                    ["Email/query", {
                        "accountId": s.account_id, "filter": filter,
                        "sort": [{ "property": "receivedAt", "isAscending": false }],
                        "position": offset, "limit": limit, "calculateTotal": true
                    }, "q"],
                    ["Email/get", {
                        "accountId": s.account_id,
                        "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" },
                        "properties": ["id", "subject", "from", "to", "receivedAt", "size", "keywords", "preview", "hasAttachment", "header:Content-Type:asRaw"]
                    }, "g"]
                ]),
            )
            .await?;
        let (q, g) = (
            r.first().cloned().unwrap_or_default(),
            r.get(1).cloned().unwrap_or_default(),
        );
        let ids: Vec<String> = q
            .get("ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let mut by_id: HashMap<String, Summary> = g
            .get("list")
            .and_then(Value::as_array)
            .map(|l| {
                l.iter()
                    .filter_map(|e| {
                        let id = e.get("id")?.as_str()?.to_string();
                        Some((
                            id.clone(),
                            Summary {
                                id,
                                subject: e
                                    .get("subject")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                from: addr_list(e.get("from").unwrap_or(&Value::Null)),
                                to: addr_list(e.get("to").unwrap_or(&Value::Null)),
                                date: e
                                    .get("receivedAt")
                                    .and_then(Value::as_str)
                                    .map(str::to_string),
                                size: e.get("size").and_then(Value::as_u64).unwrap_or(0),
                                seen: has_kw(e, "$seen"),
                                flagged: has_kw(e, "$flagged"),
                                answered: has_kw(e, "$answered"),
                                draft: has_kw(e, "$draft"),
                                attachment: e
                                    .get("hasAttachment")
                                    .and_then(Value::as_bool)
                                    .unwrap_or(false),
                                preview: e
                                    .get("preview")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                security: e
                                    .get("header:Content-Type:asRaw")
                                    .and_then(Value::as_str)
                                    .and_then(|ct| {
                                        crate::smime::kind_of(format!("Content-Type:{ct}\r\n\r\n").as_bytes())
                                    }),
                            },
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut items: Vec<Summary> = ids.iter().filter_map(|id| by_id.remove(id)).collect();
        for i in &mut items {
            if i.security == Some("encrypted") {
                i.preview.clear();
            }
        }
        let total = q
            .get("total")
            .and_then(Value::as_u64)
            .map(|t| t as usize)
            .unwrap_or(offset + items.len());
        Ok(Page {
            total,
            offset,
            items,
        })
    }

    async fn raw(&self, mailbox: &str, id: &str) -> Result<Bytes> {
        check_id(mailbox)?;
        check_id(id)?;
        let s = self.session().await?;
        let r = self
            .call(
                &s,
                json!([["Email/get", { "accountId": s.account_id, "ids": [id], "properties": ["blobId"] }, "0"]]),
            )
            .await?;
        let blob = r
            .first()
            .and_then(|a| a.pointer("/list/0/blobId"))
            .and_then(Value::as_str)
            .ok_or(Error::NotFound)?;
        let url = s
            .download_url
            .replace("{accountId}", &enc(&s.account_id))
            .replace("{blobId}", &enc(blob))
            .replace("{name}", "message.eml")
            .replace("{type}", &enc("application/octet-stream"));
        let resp = self
            .client()
            .get(&url)
            .header(header::AUTHORIZATION, self.auth())
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Err(Error::NotFound);
        }
        if !resp.status().is_success() {
            return Err(Error::upstream(format!(
                "download returned {}",
                resp.status()
            )));
        }
        Ok(resp.bytes().await?)
    }

    async fn set_flag(&self, mailbox: &str, ids: &[String], flag: Flag, on: bool) -> Result<()> {
        check_id(mailbox)?;
        check_ids(ids)?;
        let s = self.session().await?;
        let path = format!("keywords/{}", keyword(flag));
        let value = if on { Value::Bool(true) } else { Value::Null };
        let update: serde_json::Map<String, Value> = ids
            .iter()
            .map(|id| (id.clone(), json!({ path.as_str(): value })))
            .collect();
        self.email_set(&s, json!({ "update": update })).await
    }

    async fn move_to(&self, mailbox: &str, ids: &[String], dest: &str) -> Result<()> {
        check_id(mailbox)?;
        check_ids(ids)?;
        check_id(dest)?;
        let s = self.session().await?;
        let update: serde_json::Map<String, Value> = ids
            .iter()
            .map(|id| (id.clone(), json!({ "mailboxIds": { dest: true } })))
            .collect();
        self.email_set(&s, json!({ "update": update })).await
    }

    async fn destroy(&self, mailbox: &str, ids: &[String]) -> Result<()> {
        check_id(mailbox)?;
        check_ids(ids)?;
        let s = self.session().await?;
        self.email_set(&s, json!({ "destroy": ids })).await
    }

    async fn append(&self, mailbox: &str, raw: &[u8], flags: &[Flag]) -> Result<()> {
        check_id(mailbox)?;
        let s = self.session().await?;
        self.import(&s, raw, mailbox, flags).await.map(|_| ())
    }

    async fn send(&self, out: &Outgoing) -> Result<()> {
        if out.recipients.is_empty() {
            return Err(Error::bad("no recipients"));
        }
        let s = self.session().await?;
        if !s.submission {
            return Err(Error::Upstream(
                "this server does not accept mail submission over JMAP".into(),
            ));
        }
        // One round trip for what sending needs to know: an identity and a
        // folder to hold the outgoing message while it is submitted.
        let r = self
            .call(
                &s,
                json!([
                    ["Identity/get", { "accountId": s.account_id, "ids": null }, "i"],
                    ["Mailbox/get", { "accountId": s.account_id, "ids": null, "properties": ["id", "role"] }, "m"]
                ]),
            )
            .await?;
        let identities = r
            .first()
            .and_then(|a| a.get("list"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let identity = identities
            .iter()
            .find(|i| {
                i.get("email")
                    .and_then(Value::as_str)
                    .map(|e| e.eq_ignore_ascii_case(&out.from))
                    .unwrap_or(false)
            })
            .or_else(|| identities.first())
            .and_then(|i| i.get("id"))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Upstream("the account has no sending identity".into()))?
            .to_string();
        let boxes = r
            .get(1)
            .and_then(|a| a.get("list"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let by_role = |role: &str| {
            boxes
                .iter()
                .find(|m| m.get("role").and_then(Value::as_str) == Some(role))
                .and_then(|m| m.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        let holding = by_role("drafts")
            .or_else(|| out.sent_mailbox.clone())
            .or_else(|| by_role("inbox"))
            .ok_or_else(|| Error::Upstream("no folder available for sending".into()))?;

        let email_id = self
            .import(&s, &out.wire, &holding, &[Flag::Draft, Flag::Seen])
            .await?;
        let rcpt: Vec<Value> = out
            .recipients
            .iter()
            .map(|e| json!({ "email": e }))
            .collect();
        let submitted = self
            .call(
                &s,
                json!([["EmailSubmission/set", {
                    "accountId": s.account_id,
                    "create": { "s": {
                        "emailId": email_id, "identityId": identity,
                        "envelope": { "mailFrom": { "email": out.from }, "rcptTo": rcpt }
                    } },
                    "onSuccessDestroyEmail": ["#s"]
                }, "0"]]),
            )
            .await
            .and_then(|r| check_set(r.first().unwrap_or(&Value::Null)));
        if let Err(e) = submitted {
            let _ = self.email_set(&s, json!({ "destroy": [email_id] })).await;
            return Err(e);
        }
        if let Some(sent) = &out.sent_mailbox {
            if let Err(e) = self.import(&s, &out.copy, sent, &[Flag::Seen]).await {
                tracing::warn!(error = %e, "sent, but could not store the copy");
            }
        }
        Ok(())
    }

    async fn create_mailbox(&self, parent: Option<&str>, name: &str) -> Result<()> {
        if !valid_folder_name(name) {
            return Err(Error::bad("invalid folder name"));
        }
        if let Some(p) = parent {
            check_id(p)?;
        }
        let s = self.session().await?;
        self.mailbox_set(
            &s,
            json!({ "create": { "m": { "name": name.trim(), "parentId": parent } } }),
        )
        .await
    }

    async fn rename_mailbox(&self, id: &str, name: &str) -> Result<()> {
        check_id(id)?;
        if !valid_folder_name(name) {
            return Err(Error::bad("invalid folder name"));
        }
        let s = self.session().await?;
        self.mailbox_set(&s, json!({ "update": { id: { "name": name.trim() } } }))
            .await
    }

    async fn delete_mailbox(&self, id: &str) -> Result<()> {
        check_id(id)?;
        let s = self.session().await?;
        self.mailbox_set(
            &s,
            json!({ "destroy": [id], "onDestroyRemoveEmails": true }),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_urls_to_the_configured_origin() {
        let o = "https://mail.example.com";
        assert_eq!(
            pin(o, "https://evil.example/jmap/").unwrap(),
            "https://mail.example.com/jmap/"
        );
        assert_eq!(
            pin(o, "http://10.0.0.1:8080/a?b=c").unwrap(),
            "https://mail.example.com/a?b=c"
        );
        assert_eq!(
            pin(
                o,
                "https://x/jmap/download/{accountId}/{blobId}/{name}?accept={type}"
            )
            .unwrap(),
            "https://mail.example.com/jmap/download/{accountId}/{blobId}/{name}?accept={type}"
        );
        assert_eq!(
            pin(o, "/jmap/session").unwrap(),
            "https://mail.example.com/jmap/session"
        );
        assert_eq!(
            pin(o, "https://evil.example").unwrap(),
            "https://mail.example.com/"
        );
        assert!(pin(o, "//evil.example/x").is_err());
        assert!(pin(o, "ftp://x/y").is_err());
        assert!(pin(o, "/a b").is_err());
    }

    #[test]
    fn origin() {
        assert_eq!(
            origin_of("https://mail.example.com/some/path").unwrap(),
            "https://mail.example.com"
        );
        assert_eq!(
            origin_of("http://stalwart:8080").unwrap(),
            "http://stalwart:8080"
        );
    }

    #[test]
    fn ids() {
        assert!(valid_id("Mabc-123_x"));
        assert!(!valid_id("a/b"));
        assert!(!valid_id("a~b"));
        assert!(!valid_id(""));
        assert!(check_ids(&[]).is_err());
    }

    #[test]
    fn set_errors_are_reported() {
        assert!(check_set(&json!({ "updated": { "a": null } })).is_ok());
        assert!(check_set(&json!({ "notUpdated": { "a": { "type": "notFound" } } })).is_err());
        assert!(check_set(&json!({ "notCreated": {} })).is_ok());
    }
}
