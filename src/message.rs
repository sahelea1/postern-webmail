//! Turning stored messages into something safe to show, and composing new ones.

use crate::{
    backend::{Addr, Summary},
    error::{Error, Result},
    seal,
};
use mail_builder::{MessageBuilder, headers::address::Address as BAddress};
use mail_parser::{Message, MessageParser, MimeHeaders, PartType};
use serde::Serialize;
use std::{
    borrow::Cow,
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub fn parse(raw: &[u8]) -> Result<Message<'_>> {
    MessageParser::default()
        .parse(raw)
        .ok_or_else(|| Error::Upstream("message could not be parsed".into()))
}

pub fn addrs(a: Option<&mail_parser::Address<'_>>) -> Vec<Addr> {
    let Some(a) = a else { return Vec::new() };
    a.iter()
        .filter_map(|x| {
            let email = x.address()?.trim().to_string();
            if email.is_empty() {
                return None;
            }
            Some(Addr {
                name: x
                    .name()
                    .map(|n| n.trim().to_string())
                    .filter(|n| !n.is_empty() && !n.eq_ignore_ascii_case(&email)),
                email,
            })
        })
        .collect()
}

fn one_line(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() || c.is_control() {
            space = !out.is_empty();
        } else {
            if space {
                out.push(' ');
                space = false;
            }
            out.push(c);
            if out.chars().count() >= max {
                break;
            }
        }
    }
    out
}

/// Builds a list row from a message's header block plus the first bytes of its body.
pub fn summarize(head_and_some_body: &[u8]) -> Summary {
    let mut s = Summary::default();
    if let Some(m) = MessageParser::default().parse(head_and_some_body) {
        s.subject = one_line(m.subject().unwrap_or(""), 300);
        s.from = addrs(m.from());
        s.to = addrs(m.to());
        s.date = m.date().map(|d| d.to_rfc3339());
        s.preview = m
            .body_preview(220)
            .map(|p| one_line(&p, 200))
            .unwrap_or_default();
        s.security = crate::smime::kind_of(head_and_some_body);
        if s.security == Some("encrypted") {
            s.preview.clear();
        }
        s.attachment = m
            .content_type()
            .map(|ct| {
                ct.c_type.eq_ignore_ascii_case("multipart")
                    && ct
                        .c_subtype
                        .as_deref()
                        .map(|st| st.eq_ignore_ascii_case("mixed"))
                        .unwrap_or(false)
            })
            .unwrap_or(false);
    }
    s
}

#[derive(Serialize, Debug)]
pub struct AttachmentInfo {
    pub part: u32,
    pub name: String,
    pub mime: String,
    pub size: usize,
    /// Shown inside the HTML body rather than in the attachment strip.
    pub inline: bool,
}

#[derive(Serialize, Debug)]
pub struct MessageView {
    pub subject: String,
    pub from: Vec<Addr>,
    pub to: Vec<Addr>,
    pub cc: Vec<Addr>,
    pub bcc: Vec<Addr>,
    pub reply_to: Vec<Addr>,
    pub date: Option<String>,
    pub message_id: Option<String>,
    pub references: Vec<String>,
    pub text: String,
    pub has_html: bool,
    pub remote_images: bool,
    pub attachments: Vec<AttachmentInfo>,
}

fn mime_of(part: &mail_parser::MessagePart<'_>) -> String {
    match part.content_type() {
        Some(ct) => match &ct.c_subtype {
            Some(st) => format!("{}/{}", ct.c_type, st).to_ascii_lowercase(),
            None => ct.c_type.to_ascii_lowercase(),
        },
        None => match part.body {
            PartType::Message(_) => "message/rfc822".into(),
            PartType::Html(_) => "text/html".into(),
            PartType::Text(_) => "text/plain".into(),
            _ => "application/octet-stream".into(),
        },
    }
}

fn html_of<'a>(m: &'a Message<'a>) -> Option<&'a str> {
    m.html_body
        .iter()
        .find_map(|id| match &m.parts.get(*id as usize)?.body {
            PartType::Html(h) => Some(h.as_ref()),
            _ => None,
        })
}

fn clean_cid(cid: &str) -> &str {
    cid.trim().trim_start_matches('<').trim_end_matches('>')
}

/// Builds the view of a message. The header fields come from `raw`; the
/// body comes from `inner` when S/MIME unwrapping produced one.
pub fn view(raw: &[u8], inner: Option<&[u8]>) -> Result<MessageView> {
    let outer = parse(raw)?;
    let body_msg;
    let m = match inner {
        Some(b) => {
            body_msg = parse(b)?;
            &body_msg
        }
        None => &outer,
    };
    let html = html_of(m);
    let remote_images = html.map(|h| sanitize_html(h, false, "").1).unwrap_or(false);
    let text = m.body_text(0).map(|t| t.into_owned()).unwrap_or_default();

    let mut references: Vec<String> = Vec::new();
    for hv in [outer.references(), outer.in_reply_to()] {
        // `as_text` on a list yields a single entry, so the list comes first.
        match hv {
            mail_parser::HeaderValue::TextList(list) => {
                references.extend(list.iter().map(|s| s.to_string()))
            }
            mail_parser::HeaderValue::Text(t) => references.push(t.to_string()),
            _ => {}
        }
    }
    let mut seen_refs = HashSet::new();
    references.retain(|r| seen_refs.insert(r.clone()));
    references.truncate(30);

    let attachments = m
        .attachments
        .iter()
        .filter_map(|id| {
            let part = m.parts.get(*id as usize)?;
            let mime = mime_of(part);
            let inline = match (part.content_id(), html) {
                (Some(cid), Some(h)) => {
                    mime.starts_with("image/") && h.contains(&format!("cid:{}", clean_cid(cid)))
                }
                _ => false,
            };
            let fallback = if mime == "message/rfc822" {
                "message.eml"
            } else {
                "attachment"
            };
            Some(AttachmentInfo {
                part: *id,
                name: one_line(part.attachment_name().unwrap_or(fallback), 200),
                mime,
                size: part.contents().len(),
                inline,
            })
        })
        .collect();

    Ok(MessageView {
        subject: one_line(outer.subject().unwrap_or(""), 500),
        from: addrs(outer.from()),
        to: addrs(outer.to()),
        cc: addrs(outer.cc()),
        bcc: addrs(outer.bcc()),
        reply_to: addrs(outer.reply_to()),
        date: outer.date().map(|d| d.to_rfc3339()),
        message_id: outer.message_id().map(|s| s.to_string()),
        references,
        text,
        has_html: html.is_some(),
        remote_images,
        attachments,
    })
}

pub struct PartData {
    pub name: String,
    pub mime: String,
    pub data: Vec<u8>,
}

/// Returns one attachment by its part number.
pub fn part(raw: &[u8], index: u32) -> Result<PartData> {
    let m = parse(raw)?;
    if !m.attachments.contains(&index) {
        return Err(Error::NotFound);
    }
    let p = m.parts.get(index as usize).ok_or(Error::NotFound)?;
    Ok(PartData {
        name: one_line(p.attachment_name().unwrap_or("attachment"), 200),
        mime: mime_of(p),
        data: p.contents().to_vec(),
    })
}

/// Returns the inline image with the given Content-ID, if it is a raster image.
pub fn cid_image(raw: &[u8], cid: &str) -> Result<PartData> {
    let m = parse(raw)?;
    let want = clean_cid(cid);
    for p in &m.parts {
        if p.content_id().map(clean_cid) == Some(want) {
            let data = p.contents().to_vec();
            let mime = sniff_image(&data).ok_or(Error::NotFound)?;
            return Ok(PartData {
                name: String::new(),
                mime: mime.into(),
                data,
            });
        }
    }
    Err(Error::NotFound)
}

/// Decides an image type from its first bytes. Anything else, SVG included, is refused.
pub fn sniff_image(d: &[u8]) -> Option<&'static str> {
    if d.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if d.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if d.starts_with(b"GIF87a") || d.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if d.len() > 12 && &d[..4] == b"RIFF" && &d[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

// ---- HTML ------------------------------------------------------------------

const STYLE_PROPERTIES: &[&str] = &[
    "background",
    "background-color",
    "border",
    "border-bottom",
    "border-bottom-color",
    "border-bottom-style",
    "border-bottom-width",
    "border-collapse",
    "border-color",
    "border-left",
    "border-left-color",
    "border-left-style",
    "border-left-width",
    "border-radius",
    "border-right",
    "border-right-color",
    "border-right-style",
    "border-right-width",
    "border-spacing",
    "border-style",
    "border-top",
    "border-top-color",
    "border-top-style",
    "border-top-width",
    "border-width",
    "clear",
    "color",
    "direction",
    "display",
    "float",
    "font",
    "font-family",
    "font-size",
    "font-style",
    "font-variant",
    "font-weight",
    "height",
    "letter-spacing",
    "line-height",
    "list-style",
    "list-style-type",
    "margin",
    "margin-bottom",
    "margin-left",
    "margin-right",
    "margin-top",
    "max-height",
    "max-width",
    "min-height",
    "min-width",
    "overflow",
    "padding",
    "padding-bottom",
    "padding-left",
    "padding-right",
    "padding-top",
    "table-layout",
    "text-align",
    "text-decoration",
    "text-indent",
    "text-transform",
    "vertical-align",
    "white-space",
    "width",
    "word-break",
    "word-wrap",
    "overflow-wrap",
];

/// The only relative URLs that survive sanitizing are the ones the sanitizer
/// itself writes for inline images.
struct OwnUrlsOnly(String);

impl ammonia::UrlRelativeEvaluate<'static> for OwnUrlsOnly {
    fn evaluate<'url>(&self, url: &'url str) -> Option<Cow<'url, str>> {
        if !self.0.is_empty() && url.starts_with(&self.0) {
            Some(Cow::Borrowed(url))
        } else {
            None
        }
    }
}

/// Cleans message HTML down to an allow-list. Returns the clean markup and
/// whether the original referenced images on other servers.
///
/// `cid_prefix` is the URL an inline image is fetched from; the Content-ID is
/// appended, percent-encoded. With `allow_remote` false, remote image sources
/// are removed entirely.
pub fn sanitize_html(html: &str, allow_remote: bool, cid_prefix: &str) -> (String, bool) {
    let saw_remote = Arc::new(AtomicBool::new(false));
    let flag = saw_remote.clone();
    let cid_prefix = cid_prefix.to_string();
    let own_prefix = cid_prefix.clone();

    let mut b = ammonia::Builder::default();
    b.add_tags(["font", "center", "u", "big", "tt"])
        .add_generic_attributes([
            "style",
            "align",
            "valign",
            "bgcolor",
            "color",
            "width",
            "height",
            "border",
            "cellpadding",
            "cellspacing",
            "dir",
            "lang",
        ])
        .add_tag_attributes("font", ["face", "size"])
        .filter_style_properties(STYLE_PROPERTIES.iter().copied().collect::<HashSet<_>>())
        .url_schemes(["http", "https", "mailto", "cid"].into_iter().collect())
        .link_rel(Some("noopener noreferrer nofollow"))
        .set_tag_attribute_value("a", "target", "_blank")
        .url_relative(ammonia::UrlRelative::Custom(Box::new(OwnUrlsOnly(
            own_prefix,
        ))))
        .attribute_filter(move |element, attribute, value| {
            match (element, attribute) {
                ("img", "src") => {
                    let v = value.trim();
                    let lower = v.to_ascii_lowercase();
                    if let Some(cid) = lower.strip_prefix("cid:").map(|_| &v[4..]) {
                        if cid_prefix.is_empty() {
                            return None;
                        }
                        let enc = percent_encoding::utf8_percent_encode(
                            clean_cid(cid),
                            percent_encoding::NON_ALPHANUMERIC,
                        );
                        Some(Cow::Owned(format!("{cid_prefix}{enc}")))
                    } else if lower.starts_with("http://") || lower.starts_with("https://") {
                        flag.store(true, Ordering::Relaxed);
                        if allow_remote {
                            Some(Cow::Borrowed(value))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                // Inline styles may set colours and spacing, never fetch anything.
                // Backslashes are refused because CSS escapes can spell `url(` invisibly.
                (_, "style") => {
                    let v = value.to_ascii_lowercase();
                    let risky = [
                        "url",
                        "\\",
                        "@",
                        "expression",
                        "behavior",
                        "binding",
                        "javascript",
                        "image-set",
                        "image(",
                    ];
                    if risky.iter().any(|r| v.contains(r)) {
                        None
                    } else {
                        Some(Cow::Borrowed(value))
                    }
                }
                // A link to an inline part makes no sense outside the message.
                ("a", "href") if value.trim().to_ascii_lowercase().starts_with("cid:") => None,
                _ => Some(Cow::Borrowed(value)),
            }
        });
    let clean = b.clean(html).to_string();
    (clean, saw_remote.load(Ordering::Relaxed))
}

/// Wraps clean markup in a full document for the mail frame.
pub fn html_document(clean_body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"referrer\" content=\"no-referrer\">\
<style>html{{color-scheme:light}}body{{margin:0;padding:20px 24px;background:#fff;color:#1b1b1f;\
font:15px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;\
overflow-wrap:anywhere}}img{{max-width:100%;height:auto}}img:not([src]){{display:none}}table{{max-width:100%}}\
a{{color:#3b5bdb}}blockquote{{margin:0 0 0 4px;padding-left:12px;border-left:3px solid #d5d7de;color:#555}}\
pre{{white-space:pre-wrap}}</style></head><body>{clean_body}</body></html>"
    )
}

/// Renders the HTML part of a message as a document for the mail frame.
pub fn html_view(raw: &[u8], allow_remote: bool, cid_prefix: &str) -> Result<String> {
    let m = parse(raw)?;
    let html = html_of(&m).ok_or(Error::NotFound)?;
    Ok(html_document(
        &sanitize_html(html, allow_remote, cid_prefix).0,
    ))
}

// ---- Compose ---------------------------------------------------------------

pub struct Attachment {
    pub name: String,
    pub mime: String,
    pub data: Vec<u8>,
}

pub struct Compose {
    pub from_name: Option<String>,
    pub from_email: String,
    pub to: Vec<Addr>,
    pub cc: Vec<Addr>,
    pub bcc: Vec<Addr>,
    pub subject: String,
    pub text: String,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub attachments: Vec<Attachment>,
}

fn header_safe(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn valid_address(email: &str) -> bool {
    let Some((local, domain)) = email.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && email.len() <= 254
        && !email.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ',' | ';' | '"')
        })
}

/// Parses what a person typed into a recipient field: `a@b`, `Name <a@b>`,
/// several separated by commas or semicolons.
pub fn parse_recipients(input: &str) -> Result<Vec<Addr>> {
    let cleaned: String = input
        .chars()
        .map(|c| if c == ';' || c.is_control() { ',' } else { c })
        .collect();
    if cleaned.trim().trim_matches(',').trim().is_empty() {
        return Ok(Vec::new());
    }
    let fake = format!("To: {cleaned}\r\n\r\n");
    let parsed = MessageParser::default().parse(fake.as_bytes());
    let list = parsed.as_ref().map(|m| addrs(m.to())).unwrap_or_default();
    if list.is_empty() {
        return Err(Error::bad(format!(
            "Cannot read the address \"{}\"",
            one_line(input, 80)
        )));
    }
    for a in &list {
        if !valid_address(&a.email) {
            return Err(Error::bad(format!(
                "\"{}\" is not a valid address",
                one_line(&a.email, 80)
            )));
        }
    }
    Ok(list)
}

fn b_list(list: &[Addr]) -> BAddress<'static> {
    BAddress::new_list(
        list.iter()
            .map(|a| {
                BAddress::new_address(
                    a.name
                        .as_deref()
                        .map(|n| header_safe(n, 200))
                        .filter(|n| !n.is_empty()),
                    a.email.clone(),
                )
            })
            .collect(),
    )
}

fn strip_id(id: &str) -> String {
    header_safe(id, 300)
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

pub fn new_message_id(from_email: &str) -> String {
    let domain = from_email
        .rsplit_once('@')
        .map(|x| x.1)
        .unwrap_or("localhost");
    format!("{}@{}", seal::hex(&seal::random_bytes::<16>()), domain)
}

/// Serializes the message. The `Bcc` header is written only when `with_bcc` is set.
pub fn build(c: &Compose, message_id: &str, with_bcc: bool) -> Result<Vec<u8>> {
    let from = BAddress::new_address(
        c.from_name
            .as_deref()
            .map(|n| header_safe(n, 200))
            .filter(|n| !n.is_empty()),
        c.from_email.clone(),
    );
    let mut b = MessageBuilder::new()
        .from(from)
        .message_id(message_id.to_string())
        .subject(header_safe(&c.subject, 900))
        .text_body(
            c.text
                .replace("\r\n", "\n")
                .replace('\r', "\n")
                .replace('\n', "\r\n"),
        );
    if !c.to.is_empty() {
        b = b.to(b_list(&c.to));
    }
    if !c.cc.is_empty() {
        b = b.cc(b_list(&c.cc));
    }
    if with_bcc && !c.bcc.is_empty() {
        b = b.bcc(b_list(&c.bcc));
    }
    if let Some(irt) = c
        .in_reply_to
        .as_deref()
        .map(strip_id)
        .filter(|s| !s.is_empty())
    {
        b = b.in_reply_to(irt);
    }
    let refs: Vec<String> = c
        .references
        .iter()
        .map(|r| strip_id(r))
        .filter(|s| !s.is_empty())
        .collect();
    if !refs.is_empty() {
        b = b.references(refs);
    }
    for a in &c.attachments {
        let mime = if a.mime.contains('/') && !a.mime.chars().any(|ch| ch.is_control() || ch == ' ')
        {
            a.mime.clone()
        } else {
            "application/octet-stream".to_string()
        };
        b = b.attachment(mime, header_safe(&a.name, 200), a.data.clone());
    }
    b.write_to_vec()
        .map_err(|e| Error::Internal(format!("building message: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(html: &str) -> String {
        sanitize_html(html, false, "/api/message/cid?x=1&cid=").0
    }

    #[test]
    fn strips_active_content() {
        let cases = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)><script>alert(1)</script></svg>",
            "<a href=\"javascript:alert(1)\">x</a>",
            "<a href=\"JaVaScRiPt:alert(1)\">x</a>",
            "<a href=\"data:text/html,<script>alert(1)</script>\">x</a>",
            "<iframe src=\"https://evil.example\"></iframe>",
            "<object data=x></object><embed src=x>",
            "<form action=\"https://evil.example\"><input name=p><button>go</button></form>",
            "<meta http-equiv=\"refresh\" content=\"0;url=https://evil.example\">",
            "<base href=\"https://evil.example/\">",
            "<link rel=stylesheet href=\"https://evil.example/x.css\">",
            "<style>@import url(https://evil.example/x.css);body{background:url(https://evil.example/t)}</style>",
            "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;img src=1 onerror=alert(1)&gt;\">",
            "<div style=\"background:url(javascript:alert(1))\" onclick=\"alert(1)\">x</div>",
            "<body onload=alert(1)>",
            "<video src=x onerror=alert(1)></video><audio src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>x</details>",
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        ];
        for c in cases {
            let out = clean(c).to_ascii_lowercase();
            for bad in [
                "<script",
                "onerror",
                "onload",
                "onclick",
                "ontoggle",
                "javascript:",
                "<iframe",
                "<object",
                "<embed",
                "<form",
                "<input",
                "<button",
                "<meta",
                "<base",
                "<link",
                "<style",
                "<svg",
                "<math",
                "data:text",
                "@import",
                "<video",
                "<audio",
            ] {
                assert!(!out.contains(bad), "{bad:?} survived in {out:?} from {c:?}");
            }
        }
    }

    #[test]
    fn styles_cannot_fetch() {
        for style in [
            "background:url(https://t.example/a.png)",
            "background: URL('https://t.example/a.png')",
            "background:u\\72l(https://t.example/a.png)",
            "background-image:\\75rl(https://t.example/a.png)",
            "width:expression(alert(1))",
            "behavior:url(x.htc)",
            "-moz-binding:url(x.xml)",
            "background:image-set('https://t.example/a.png' 1x)",
        ] {
            let out = clean(&format!("<div style=\"color:red;{style}\">x</div>"));
            assert!(!out.contains("style="), "style survived: {out}");
            assert!(!out.contains("t.example"), "{out}");
        }
        assert!(clean("<p style=\"color:#333;margin:0 0 8px\">x</p>").contains("color:#333"));
    }

    #[test]
    fn remote_images_are_removed_and_reported() {
        let (out, remote) = sanitize_html(
            "<p>hi</p><img src=\"https://t.example/p.gif\" width=1>",
            false,
            "/c?cid=",
        );
        assert!(remote);
        assert!(!out.contains("t.example"));
        let (out, remote) = sanitize_html("<img src=\"https://t.example/p.gif\">", true, "/c?cid=");
        assert!(remote);
        assert!(out.contains("https://t.example/p.gif"));
        let (_, remote) = sanitize_html("<p>plain</p>", false, "/c?cid=");
        assert!(!remote);
    }

    #[test]
    fn inline_images_are_rewritten() {
        let out = clean("<img src=\"cid:logo@x\" alt=l>");
        assert!(
            out.contains("/api/message/cid?x=1&amp;cid=logo%40x"),
            "{out}"
        );
    }

    #[test]
    fn relative_and_local_urls_are_dropped() {
        let out = clean(
            "<img src=\"/api/logout\"><a href=\"/api/x\">l</a><img src=\"//evil.example/x\">",
        );
        assert!(!out.contains("/api/logout"));
        assert!(!out.contains("/api/x"));
        assert!(!out.contains("evil.example"));
    }

    #[test]
    fn links_open_safely() {
        let out = clean("<a href=\"https://example.com/a\">l</a>");
        assert!(out.contains("target=\"_blank\""));
        assert!(out.contains("noopener"));
        assert!(out.contains("noreferrer"));
    }

    #[test]
    fn keeps_layout_and_safe_styles() {
        let out = clean(
            "<table width=\"600\" bgcolor=\"#eee\"><tr><td style=\"color:red;position:fixed;padding:4px\">x</td></tr></table>",
        );
        assert!(out.contains("<table"));
        assert!(out.contains("color:red"));
        assert!(out.contains("padding:4px"));
        assert!(!out.contains("position"));
    }

    const SAMPLE: &[u8] = b"From: \"Ann Example\" <ann@example.com>\r\n\
To: bob@example.org, \"Carl\" <carl@example.org>\r\n\
Cc: dora@example.org\r\n\
Subject: =?utf-8?q?Gr=C3=BC=C3=9Fe?= from Ann\r\n\
Date: Sat, 21 Nov 2026 10:00:00 +0100\r\n\
Message-ID: <m1@example.com>\r\n\
References: <r0@example.com> <r1@example.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n\
--b1\r\n\
Content-Type: multipart/alternative; boundary=\"b2\"\r\n\r\n\
--b2\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\n\
Hello Bob,\r\nplain text here.\r\n\
--b2\r\n\
Content-Type: text/html; charset=utf-8\r\n\r\n\
<p>Hello <b>Bob</b><script>alert(1)</script><img src=\"https://t.example/p.gif\"></p>\r\n\
--b2--\r\n\
--b1\r\n\
Content-Type: application/pdf; name=\"report.pdf\"\r\n\
Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
JVBERi0xLjQK\r\n\
--b1--\r\n";

    #[test]
    fn view_extracts_everything() {
        let v = view(SAMPLE, None).unwrap();
        assert_eq!(v.subject, "Gr\u{fc}\u{df}e from Ann");
        assert_eq!(v.from[0].email, "ann@example.com");
        assert_eq!(v.from[0].name.as_deref(), Some("Ann Example"));
        assert_eq!(v.to.len(), 2);
        assert_eq!(v.cc[0].email, "dora@example.org");
        assert!(v.text.contains("plain text here"));
        assert!(v.has_html);
        assert!(v.remote_images);
        assert_eq!(v.message_id.as_deref(), Some("m1@example.com"));
        assert_eq!(v.references.len(), 2, "{:?}", v.references);
        assert_eq!(v.attachments.len(), 1);
        assert_eq!(v.attachments[0].name, "report.pdf");
        assert_eq!(v.attachments[0].mime, "application/pdf");
        let p = part(SAMPLE, v.attachments[0].part).unwrap();
        assert_eq!(p.data, b"%PDF-1.4\n");
        assert!(part(SAMPLE, 0).is_err());
        assert!(part(SAMPLE, 99).is_err());
    }

    #[test]
    fn html_view_is_clean() {
        let doc = html_view(SAMPLE, false, "/c?cid=").unwrap();
        assert!(doc.contains("<b>Bob</b>"));
        assert!(!doc.contains("<script>alert"));
        assert!(!doc.contains("t.example"));
    }

    #[test]
    fn summary_from_head() {
        let s = summarize(SAMPLE);
        assert_eq!(s.subject, "Gr\u{fc}\u{df}e from Ann");
        assert!(s.attachment);
        assert!(s.preview.starts_with("Hello Bob"));
        assert_eq!(s.date.as_deref(), Some("2026-11-21T10:00:00+01:00"));
    }

    #[test]
    fn recipients() {
        let r =
            parse_recipients("a@example.com; \"Bee, B\" <b@example.com>, c@example.com").unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[1].name.as_deref(), Some("Bee, B"));
        assert_eq!(r[1].email, "b@example.com");
        assert!(parse_recipients("").unwrap().is_empty());
        assert!(parse_recipients("not an address").is_err());
        assert!(
            parse_recipients("a@example.com\r\nBcc: evil@example.com")
                .map(|l| l.len())
                .unwrap_or(0)
                <= 2
        );
    }

    #[test]
    fn build_roundtrip_and_no_header_injection() {
        let c = Compose {
            from_name: Some("Me\r\nBcc: evil@example.com".into()),
            from_email: "me@example.com".into(),
            to: vec![Addr {
                name: Some("Bob".into()),
                email: "bob@example.org".into(),
            }],
            cc: vec![],
            bcc: vec![Addr {
                name: None,
                email: "secret@example.org".into(),
            }],
            subject: "Hi\r\nX-Evil: 1".into(),
            text: "line one\nline two \u{fc}".into(),
            in_reply_to: Some("<m1@example.com>".into()),
            references: vec!["<r0@example.com>".into(), "m1@example.com".into()],
            attachments: vec![Attachment {
                name: "a.txt".into(),
                mime: "text/plain".into(),
                data: b"data".to_vec(),
            }],
        };
        let id = new_message_id(&c.from_email);
        let wire = build(&c, &id, false).unwrap();
        let copy = build(&c, &id, true).unwrap();
        let wire_s = String::from_utf8_lossy(&wire);
        assert!(!wire_s.contains("secret@example.org"));
        assert!(String::from_utf8_lossy(&copy).contains("secret@example.org"));
        assert!(!wire_s.contains("\r\nX-Evil:"));
        assert!(!wire_s.contains("\r\nBcc: evil"));
        let m = parse(&wire).unwrap();
        assert_eq!(m.message_id(), Some(id.as_str()));
        assert_eq!(
            m.from().unwrap().first().unwrap().address(),
            Some("me@example.com")
        );
        assert!(m.body_text(0).unwrap().contains("line two \u{fc}"));
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.in_reply_to().as_text(), Some("m1@example.com"));
        let v = view(&copy, None).unwrap();
        assert_eq!(v.bcc[0].email, "secret@example.org");
    }

    #[test]
    fn image_sniffing() {
        assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(
            sniff_image(b"<svg xmlns='http://www.w3.org/2000/svg'>"),
            None
        );
        assert_eq!(sniff_image(b"<html>"), None);
    }
}
