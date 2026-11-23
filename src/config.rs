//! Static settings come from environment variables; the list of mail servers
//! lives in `servers.toml` inside the data directory and can be changed at
//! runtime by the admin console.

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub admin_listen: Option<SocketAddr>,
    pub admin_url: String,
    pub data_dir: PathBuf,
    /// Cookies get `Secure` and the `__Host-` prefix. Only off for local development.
    pub secure_cookies: bool,
    /// Take the client address from `X-Forwarded-For` (set this behind a reverse proxy).
    pub trust_proxy: bool,
    pub session_hours: u64,
    pub max_upload_mb: usize,
    pub brand: String,
    /// When set, the server list is read from this file and the admin console
    /// cannot change it (for configuration managed elsewhere, e.g. a ConfigMap).
    pub servers_file: Option<PathBuf>,
    /// Extra trust anchors for S/MIME signatures (PEM), next to the built-in Mozilla list.
    pub smime_ca_file: Option<String>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn env_bool(name: &str, default: bool) -> bool {
    match env(name).map(|v| v.to_ascii_lowercase()) {
        Some(v) => matches!(v.as_str(), "1" | "true" | "yes" | "on"),
        None => default,
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let listen = env("POSTERN_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".into());
        let listen = listen.parse().map_err(|e| format!("POSTERN_LISTEN: {e}"))?;
        let admin = env("POSTERN_ADMIN_LISTEN").unwrap_or_else(|| "127.0.0.1:8081".into());
        let admin_listen = if admin.eq_ignore_ascii_case("off") {
            None
        } else {
            Some(
                admin
                    .parse()
                    .map_err(|e| format!("POSTERN_ADMIN_LISTEN: {e}"))?,
            )
        };
        let num = |name: &str, default: u64| -> Result<u64, String> {
            match env(name) {
                Some(v) => v.parse().map_err(|e| format!("{name}: {e}")),
                None => Ok(default),
            }
        };
        Ok(Config {
            listen,
            admin_listen,
            admin_url: env("POSTERN_ADMIN_URL").unwrap_or_else(|| "http://127.0.0.1:8081".into()),
            data_dir: env("POSTERN_DATA_DIR")
                .unwrap_or_else(|| "./data".into())
                .into(),
            secure_cookies: !env_bool("POSTERN_INSECURE_HTTP", false),
            trust_proxy: env_bool("POSTERN_TRUST_PROXY", false),
            session_hours: num("POSTERN_SESSION_HOURS", 168)?.clamp(1, 24 * 90),
            max_upload_mb: num("POSTERN_MAX_UPLOAD_MB", 25)?.clamp(1, 200) as usize,
            brand: env("POSTERN_BRAND").unwrap_or_else(|| "Postern".into()),
            servers_file: env("POSTERN_SERVERS_FILE").map(PathBuf::from),
            smime_ca_file: env("POSTERN_SMIME_CA_FILE"),
        })
    }

    pub fn servers_file(&self) -> PathBuf {
        self.servers_file
            .clone()
            .unwrap_or_else(|| self.data_dir.join("servers.toml"))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Imap,
    Jmap,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS from the first byte (IMAP 993, SMTP 465).
    #[default]
    Tls,
    /// Plain connection upgraded with STARTTLS (IMAP 143, SMTP 587).
    Starttls,
    /// No encryption. Only for a server on the same host or a private network.
    None,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum UsernameStyle {
    /// Sign in to the mail server with the full address.
    #[default]
    Email,
    /// Sign in with the part before the `@`.
    Local,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RemoteImages {
    /// Hidden until the reader asks for them.
    #[default]
    Ask,
    /// Never loaded.
    Never,
}

fn d_true() -> bool {
    true
}
fn d_imap_port() -> u16 {
    993
}
fn d_smtp_port() -> u16 {
    465
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServerCfg {
    pub id: String,
    #[serde(default)]
    pub name: String,
    /// Domains whose addresses may sign in here. `*.example.com` matches
    /// subdomains, `*` matches everything.
    pub domains: Vec<String>,
    #[serde(default)]
    pub protocol: Protocol,
    #[serde(default = "d_true")]
    pub enabled: bool,
    #[serde(default)]
    pub username: UsernameStyle,
    /// Accept invalid TLS certificates. Leave off unless you know why you need it.
    #[serde(default)]
    pub tls_insecure: bool,
    #[serde(default)]
    pub remote_images: RemoteImages,

    // IMAP + SMTP
    #[serde(default)]
    pub imap_host: String,
    #[serde(default = "d_imap_port")]
    pub imap_port: u16,
    #[serde(default)]
    pub imap_security: Security,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default = "d_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_security: Security,
    /// Store a copy in the Sent folder after sending. Turn off for servers
    /// that do this themselves (Gmail does).
    #[serde(default = "d_true")]
    pub save_sent: bool,

    // JMAP
    #[serde(default)]
    pub jmap_url: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Servers {
    #[serde(default, rename = "server")]
    pub servers: Vec<ServerCfg>,
}

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_' | '[' | ']'))
}

fn valid_domain_pattern(d: &str) -> bool {
    if d == "*" {
        return true;
    }
    let body = d.strip_prefix("*.").unwrap_or(d);
    !body.is_empty()
        && body.contains('.')
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && !body.starts_with('.')
        && !body.ends_with('.')
}

impl Servers {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut s: Servers = toml::from_str(text).map_err(|e| e.to_string())?;
        s.normalize();
        s.validate()?;
        Ok(s)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    pub fn normalize(&mut self) {
        for s in &mut self.servers {
            s.id = s.id.trim().to_string();
            s.name = s.name.trim().to_string();
            s.imap_host = s.imap_host.trim().to_string();
            s.smtp_host = s.smtp_host.trim().to_string();
            s.jmap_url = s.jmap_url.trim().trim_end_matches('/').to_string();
            s.domains = s
                .domains
                .iter()
                .map(|d| d.trim().to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect();
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut ids = HashSet::new();
        let mut domains = HashSet::new();
        for s in &self.servers {
            let label = if s.id.is_empty() { "(no id)" } else { &s.id };
            if s.id.is_empty()
                || s.id.len() > 32
                || !s
                    .id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(format!(
                    "server {label}: id must be 1-32 letters, digits, '-' or '_'"
                ));
            }
            if !ids.insert(s.id.clone()) {
                return Err(format!("server {label}: duplicate id"));
            }
            if s.domains.is_empty() {
                return Err(format!("server {label}: needs at least one domain"));
            }
            for d in &s.domains {
                if !valid_domain_pattern(d) {
                    return Err(format!("server {label}: invalid domain '{d}'"));
                }
                if s.enabled && !domains.insert(d.clone()) {
                    return Err(format!(
                        "server {label}: domain '{d}' is already used by another server"
                    ));
                }
            }
            match s.protocol {
                Protocol::Imap => {
                    if !valid_host(&s.imap_host) || !valid_host(&s.smtp_host) {
                        return Err(format!(
                            "server {label}: imap_host and smtp_host are required"
                        ));
                    }
                    if s.imap_port == 0 || s.smtp_port == 0 {
                        return Err(format!("server {label}: ports must not be 0"));
                    }
                }
                Protocol::Jmap => {
                    let url = reqwest::Url::parse(&s.jmap_url)
                        .map_err(|_| format!("server {label}: jmap_url is not a valid URL"))?;
                    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
                        return Err(format!("server {label}: jmap_url must be http(s)"));
                    }
                    if !url.username().is_empty() || url.password().is_some() {
                        return Err(format!(
                            "server {label}: jmap_url must not contain credentials"
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Finds the enabled server responsible for an address. Exact domains win
    /// over wildcards, and longer wildcards win over shorter ones.
    pub fn for_email(&self, email: &str) -> Option<&ServerCfg> {
        let domain = email.rsplit_once('@')?.1.to_ascii_lowercase();
        let mut best: Option<(usize, &ServerCfg)> = None;
        for s in self.servers.iter().filter(|s| s.enabled) {
            for d in &s.domains {
                let score = if *d == domain {
                    usize::MAX
                } else if d == "*" {
                    1
                } else if let Some(suffix) = d.strip_prefix("*.") {
                    if domain.ends_with(&format!(".{suffix}")) {
                        2 + suffix.len()
                    } else {
                        0
                    }
                } else {
                    0
                };
                if score > 0 && best.map(|(b, _)| score > b).unwrap_or(true) {
                    best = Some((score, s));
                }
            }
        }
        best.map(|(_, s)| s)
    }

    #[cfg(test)]
    pub fn by_id(&self, id: &str) -> Option<&ServerCfg> {
        self.servers.iter().find(|s| s.id == id && s.enabled)
    }
}

/// Splits and checks a login address. Returns the lower-cased address.
pub fn normalize_email(input: &str) -> Option<String> {
    let e = input.trim().to_ascii_lowercase();
    let (local, domain) = e.rsplit_once('@')?;
    if local.is_empty()
        || domain.is_empty()
        || e.len() > 254
        || e.chars().any(|c| c.is_whitespace() || c.is_control())
        || !domain.contains('.') && domain != "localhost"
    {
        return None;
    }
    Some(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[[server]]
id = "main"
domains = ["example.com", "*.corp.example"]
protocol = "imap"
imap_host = "imap.example.com"
smtp_host = "smtp.example.com"

[[server]]
id = "jm"
domains = ["jmap.example"]
protocol = "jmap"
jmap_url = "https://mail.jmap.example/"

[[server]]
id = "any"
domains = ["*"]
imap_host = "h"
smtp_host = "h"
"#;

    #[test]
    fn parses_and_matches() {
        let s = Servers::parse(SAMPLE).unwrap();
        assert_eq!(s.for_email("a@example.com").unwrap().id, "main");
        assert_eq!(s.for_email("a@x.corp.example").unwrap().id, "main");
        assert_eq!(s.for_email("a@JMAP.example").unwrap().id, "jm");
        assert_eq!(s.for_email("a@other.org").unwrap().id, "any");
        assert_eq!(s.servers[1].jmap_url, "https://mail.jmap.example");
        assert_eq!(s.servers[0].imap_port, 993);
        assert!(s.for_email("nodomain").is_none());
    }

    #[test]
    fn exact_beats_wildcard() {
        let s = Servers::parse(SAMPLE).unwrap();
        assert_eq!(s.for_email("a@corp.example").unwrap().id, "any");
    }

    #[test]
    fn rejects_bad_configs() {
        assert!(
            Servers::parse(
                "[[server]]\nid=\"a b\"\ndomains=[\"x.y\"]\nimap_host=\"h\"\nsmtp_host=\"h\""
            )
            .is_err()
        );
        assert!(
            Servers::parse("[[server]]\nid=\"a\"\ndomains=[]\nimap_host=\"h\"\nsmtp_host=\"h\"")
                .is_err()
        );
        assert!(
            Servers::parse(
                "[[server]]\nid=\"a\"\ndomains=[\"x.y\"]\nprotocol=\"jmap\"\njmap_url=\"ftp://x\""
            )
            .is_err()
        );
        assert!(Servers::parse("[[server]]\nid=\"a\"\ndomains=[\"x.y\"]\nprotocol=\"jmap\"\njmap_url=\"https://u:p@x\"").is_err());
        assert!(Servers::parse("[[server]]\nid=\"a\"\ndomains=[\"x.y\"]\nimap_host=\"h\"\nsmtp_host=\"h\"\n[[server]]\nid=\"b\"\ndomains=[\"x.y\"]\nimap_host=\"h\"\nsmtp_host=\"h\"").is_err());
        assert!(
            Servers::parse(
                "[[server]]\nid=\"a\"\ndomains=[\"x.y\"]\nimap_host=\"\"\nsmtp_host=\"h\""
            )
            .is_err()
        );
    }

    #[test]
    fn disabled_servers_do_not_match() {
        let mut s = Servers::parse(SAMPLE).unwrap();
        s.servers[0].enabled = false;
        assert_eq!(s.for_email("a@example.com").unwrap().id, "any");
        assert!(s.by_id("main").is_none());
    }

    #[test]
    fn email_normalization() {
        assert_eq!(normalize_email(" A@Example.COM ").unwrap(), "a@example.com");
        assert!(normalize_email("a b@example.com").is_none());
        assert!(normalize_email("@example.com").is_none());
        assert!(normalize_email("a@").is_none());
        assert!(normalize_email("a@nodot").is_none());
    }

    #[test]
    fn roundtrip() {
        let s = Servers::parse(SAMPLE).unwrap();
        assert_eq!(Servers::parse(&s.to_toml()).unwrap(), s);
    }
}
