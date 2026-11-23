//! One narrow interface over two kinds of mail server. Everything the web
//! client can do goes through [`Backend`]; IMAP+SMTP and JMAP each implement it.

pub mod imap;
pub mod jmap;

use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use serde::Serialize;
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct MailboxInfo {
    /// Opaque identifier, passed back unchanged by the client.
    pub id: String,
    /// Last path component, for display.
    pub name: String,
    pub parent: Option<String>,
    /// inbox, drafts, sent, trash, junk, archive
    pub role: Option<String>,
    pub total: u32,
    pub unread: u32,
    pub selectable: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Default)]
pub struct Addr {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct Summary {
    pub id: String,
    pub subject: String,
    pub from: Vec<Addr>,
    pub to: Vec<Addr>,
    /// RFC 3339
    pub date: Option<String>,
    pub size: u64,
    pub seen: bool,
    pub flagged: bool,
    pub answered: bool,
    pub draft: bool,
    pub attachment: bool,
    pub preview: String,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct Page {
    pub total: usize,
    pub offset: usize,
    pub items: Vec<Summary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    Seen,
    Flagged,
    Answered,
    Draft,
}

impl Flag {
    pub fn parse(s: &str) -> Option<Flag> {
        Some(match s {
            "seen" => Flag::Seen,
            "flagged" => Flag::Flagged,
            "answered" => Flag::Answered,
            "draft" => Flag::Draft,
            _ => return None,
        })
    }
}

/// A message ready to leave.
pub struct Outgoing {
    pub from: String,
    pub recipients: Vec<String>,
    /// What goes on the wire: no `Bcc` header.
    pub wire: Vec<u8>,
    /// What is kept in the Sent folder: includes `Bcc`.
    pub copy: Vec<u8>,
    pub sent_mailbox: Option<String>,
}

#[async_trait]
pub trait Backend: Send + Sync {
    /// Signs in and returns, used to check credentials.
    async fn verify(&self) -> Result<()>;
    async fn mailboxes(&self) -> Result<Vec<MailboxInfo>>;
    async fn list(
        &self,
        mailbox: &str,
        offset: usize,
        limit: usize,
        query: Option<&str>,
    ) -> Result<Page>;
    /// The complete message as stored (RFC 5322 bytes).
    async fn raw(&self, mailbox: &str, id: &str) -> Result<Bytes>;
    async fn set_flag(&self, mailbox: &str, ids: &[String], flag: Flag, on: bool) -> Result<()>;
    async fn move_to(&self, mailbox: &str, ids: &[String], dest: &str) -> Result<()>;
    /// Removes messages for good.
    async fn destroy(&self, mailbox: &str, ids: &[String]) -> Result<()>;
    async fn append(&self, mailbox: &str, raw: &[u8], flags: &[Flag]) -> Result<()>;
    /// Sends the message and files the copy in `sent_mailbox` when given.
    async fn send(&self, out: &Outgoing) -> Result<()>;
    async fn create_mailbox(&self, parent: Option<&str>, name: &str) -> Result<()>;
    async fn rename_mailbox(&self, id: &str, name: &str) -> Result<()>;
    async fn delete_mailbox(&self, id: &str) -> Result<()>;
}

/// Guesses a folder's purpose from its name when the server does not say.
pub fn role_from_name(name: &str) -> Option<&'static str> {
    let n = name.trim().to_lowercase();
    Some(match n.as_str() {
        "inbox" | "posteingang" => "inbox",
        "sent" | "sent items" | "sent messages" | "sent mail" | "gesendet"
        | "gesendete elemente" | "gesendete objekte" => "sent",
        "drafts" | "draft" | "entw\u{fc}rfe" => "drafts",
        "trash"
        | "deleted items"
        | "deleted messages"
        | "bin"
        | "papierkorb"
        | "gel\u{f6}schte elemente" => "trash",
        "junk" | "spam" | "junk e-mail" | "junk email" | "bulk mail" => "junk",
        "archive" | "archives" | "archiv" => "archive",
        _ => return None,
    })
}

/// Folder names are shown as-is but must not contain control characters or be huge.
pub fn valid_folder_name(name: &str) -> bool {
    let n = name.trim();
    !n.is_empty() && n.chars().count() <= 100 && !n.chars().any(|c| c.is_control())
}

// ---- TLS -------------------------------------------------------------------

mod danger {
    use rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
        pki_types::{CertificateDer, ServerName, UnixTime},
    };
    use std::sync::Arc;

    /// Accepts any certificate. Only used for servers flagged `tls_insecure`.
    #[derive(Debug)]
    pub struct AcceptAny(pub Arc<CryptoProvider>);

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

pub fn tls_config(insecure: bool) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("TLS protocol versions");
    let cfg = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::AcceptAny(provider)))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Extra trust anchors for private CAs: a PEM bundle named by POSTERN_CA_FILE.
        if let Ok(path) = std::env::var("POSTERN_CA_FILE") {
            if let Ok(pem) = std::fs::read(&path) {
                for cert in rustls_pemfile::certs(&mut pem.as_slice()).flatten() {
                    let _ = roots.add(cert);
                }
            }
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Arc::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        assert_eq!(role_from_name("Sent Items"), Some("sent"));
        assert_eq!(role_from_name("Entw\u{fc}rfe"), Some("drafts"));
        assert_eq!(role_from_name("INBOX"), Some("inbox"));
        assert_eq!(role_from_name("Projects"), None);
    }

    #[test]
    fn folder_names() {
        assert!(valid_folder_name("Projects 2026"));
        assert!(!valid_folder_name("  "));
        assert!(!valid_folder_name("a\r\nb"));
    }
}
