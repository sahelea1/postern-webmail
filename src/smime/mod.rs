//! S/MIME (RFC 8551) on CMS (RFC 5652): signing, encrypting, verifying and
//! decrypting, for messages as they pass through the gateway.
//!
//! Where the keys are:
//! - The user's private key never touches the disk. On import it is sealed
//!   with the server key, bound to the user's address, and handed to the
//!   browser, which sends it back with the requests that need it.
//! - Certificates of other people are public; the browser keeps them.
//! - Trust anchors are Mozilla's roots for e-mail (roots.pem), plus any file
//!   named in POSTERN_SMIME_CA_FILE.
//!
//! What is done where: only the top level of a message is unwrapped (a signed
//! or encrypted message as a whole), never an encrypted part inside some
//! other multipart. That is the usual defence against EFAIL-style mixing.

pub mod asn1;

use crate::{
    error::{Error, Result},
    seal::{self, Sealer},
};
use asn1::{Node, OCTET_STRING, OCTET_STRING_C, SEQUENCE, SET, oid_is};
use base64::{
    Engine,
    alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::STANDARD as B64},
};
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use mail_parser::{MessageParser, MimeHeaders};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{self, EcdsaKeyPair, RsaKeyPair, UnparsedPublicKey, VerificationAlgorithm},
};
use rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, time::Duration};
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

// ---- object identifiers ----------------------------------------------------

const DATA: &str = "1.2.840.113549.1.7.1";
const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
const AUTH_ENVELOPED_DATA: &str = "1.2.840.113549.1.9.16.1.23";
const ATTR_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const ATTR_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const ATTR_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const ATTR_SMIME_CAPS: &str = "1.2.840.113549.1.9.15";
const ATTR_ENC_KEY_PREF: &str = "1.2.840.113549.1.9.16.2.11";
const ATTR_MS_ENC_KEY_PREF: &str = "1.3.6.1.4.1.311.16.4";
const SHA1: &str = "1.3.14.3.2.26";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const SHA384: &str = "2.16.840.1.101.3.4.2.2";
const SHA512: &str = "2.16.840.1.101.3.4.2.3";
const RSA: &str = "1.2.840.113549.1.1.1";
const RSA_SHA1: &str = "1.2.840.113549.1.1.5";
const RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const RSA_SHA384: &str = "1.2.840.113549.1.1.12";
const RSA_SHA512: &str = "1.2.840.113549.1.1.13";
const RSA_PSS: &str = "1.2.840.113549.1.1.10";
const RSA_OAEP: &str = "1.2.840.113549.1.1.7";
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
const CURVE_P256: &str = "1.2.840.10045.3.1.7";
const CURVE_P384: &str = "1.3.132.0.34";
const AES128_CBC: &str = "2.16.840.1.101.3.4.1.2";
const AES192_CBC: &str = "2.16.840.1.101.3.4.1.22";
const AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";
const DES_EDE3_CBC: &str = "1.2.840.113549.3.7";
/// id-kp-emailProtection (1.3.6.1.5.5.7.3.4), content bytes.
const EMAIL_PROTECTION: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];

const SEAL_CONTEXT: &str = "postern-smime-v1";

fn at<'a>(v: &[Node<'a>], i: usize) -> asn1::R<Node<'a>> {
    v.get(i).copied().ok_or(asn1::Asn1Error("missing element"))
}

// ---- hashes ----------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn from_oid(o: &[u8]) -> Option<Hash> {
        if oid_is(o, SHA1) {
            Some(Hash::Sha1)
        } else if oid_is(o, SHA256) {
            Some(Hash::Sha256)
        } else if oid_is(o, SHA384) {
            Some(Hash::Sha384)
        } else if oid_is(o, SHA512) {
            Some(Hash::Sha512)
        } else {
            None
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        let alg = match self {
            Hash::Sha1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            Hash::Sha256 => &ring::digest::SHA256,
            Hash::Sha384 => &ring::digest::SHA384,
            Hash::Sha512 => &ring::digest::SHA512,
        };
        ring::digest::digest(alg, data).as_ref().to_vec()
    }

    fn oid(self) -> &'static str {
        match self {
            Hash::Sha1 => SHA1,
            Hash::Sha256 => SHA256,
            Hash::Sha384 => SHA384,
            Hash::Sha512 => SHA512,
        }
    }

    fn micalg(self) -> &'static str {
        match self {
            Hash::Sha1 => "sha-1",
            Hash::Sha256 => "sha-256",
            Hash::Sha384 => "sha-384",
            Hash::Sha512 => "sha-512",
        }
    }
}

// ---- certificates ----------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
enum KeyKind {
    Rsa(usize),
    P256,
    P384,
    Other,
}

/// A parsed certificate with the fields S/MIME needs.
#[derive(Clone, Debug)]
pub struct Cert {
    pub der: Vec<u8>,
    issuer_raw: Vec<u8>,
    serial: Vec<u8>,
    ski: Option<Vec<u8>>,
    kind: KeyKind,
    /// RSA: the RSAPublicKey DER. EC: the uncompressed point.
    public_key: Vec<u8>,
    pub emails: Vec<String>,
    not_before: i64,
    not_after: i64,
    ku_encipher: Option<bool>,
    ku_sign: Option<bool>,
    name: String,
    subject: String,
    issuer: String,
}

/// What the browser is told about a certificate.
#[derive(Serialize, Clone, Debug)]
pub struct CertInfo {
    pub fingerprint: String,
    pub name: String,
    pub subject: String,
    pub issuer: String,
    pub emails: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub key: String,
    pub can_encrypt: bool,
    pub can_sign: bool,
    /// trusted | expired | untrusted | invalid
    pub trust: &'static str,
    pub trust_detail: String,
    pub der: String,
}

fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|x| **x == 0).count();
    if n == b.len() { &b[b.len().saturating_sub(1)..] } else { &b[n..] }
}

fn iso(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}

impl Cert {
    pub fn parse(input: &[u8]) -> Result<Cert> {
        let not_cert = || Error::bad("this is not a certificate");
        let top = asn1::read(input).map_err(|_| not_cert())?.0;
        let der = top.raw.to_vec();
        // The fields signatures and recipient lookups compare byte for byte.
        let tbs = at(&top.children().map_err(|_| not_cert())?, 0).map_err(|_| not_cert())?;
        let f = tbs.children().map_err(|_| not_cert())?;
        let i = usize::from(f.first().map(|n| n.tag) == Some(0xa0));
        let serial = at(&f, i).map_err(|_| not_cert())?.content.to_vec();
        let issuer_raw = at(&f, i + 2).map_err(|_| not_cert())?.raw.to_vec();
        let subject_raw = at(&f, i + 4).map_err(|_| not_cert())?.raw.to_vec();
        let spki = at(&f, i + 5).map_err(|_| not_cert())?;
        let (kind, public_key) = spki_key(spki).map_err(|_| not_cert())?;

        let (_, c) = X509Certificate::from_der(&der).map_err(|_| not_cert())?;
        let mut emails: Vec<String> = Vec::new();
        if let Ok(Some(san)) = c.subject_alternative_name() {
            for g in &san.value.general_names {
                if let GeneralName::RFC822Name(e) = g {
                    emails.push(e.trim().to_ascii_lowercase());
                }
            }
        }
        for e in c.subject().iter_email() {
            if let Ok(s) = e.as_str() {
                emails.push(s.trim().to_ascii_lowercase());
            }
        }
        emails.retain(|e| e.contains('@'));
        emails.sort();
        emails.dedup();
        let (ku_encipher, ku_sign) = match c.key_usage() {
            Ok(Some(ku)) => (
                Some(ku.value.key_encipherment() || ku.value.key_agreement()),
                Some(ku.value.digital_signature() || ku.value.non_repudiation()),
            ),
            _ => (None, None),
        };
        let ski = c.iter_extensions().find_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
            _ => None,
        });
        let name = c
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_string)
            .or_else(|| emails.first().cloned())
            .unwrap_or_else(|| c.subject().to_string());
        let issuer_name = c
            .issuer()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| c.issuer().to_string());
        let _ = subject_raw;
        Ok(Cert {
            issuer_raw,
            serial,
            ski,
            kind,
            public_key,
            emails,
            not_before: c.validity().not_before.timestamp(),
            not_after: c.validity().not_after.timestamp(),
            ku_encipher,
            ku_sign,
            name,
            subject: c.subject().to_string(),
            issuer: issuer_name,
            der,
        })
    }

    pub fn not_after(&self) -> i64 {
        self.not_after
    }

    pub fn fingerprint(&self) -> String {
        seal::hex(&Hash::Sha256.digest(&self.der))
    }

    fn valid_now(&self) -> bool {
        let now = seal::unix_now() as i64;
        self.not_before <= now && now <= self.not_after
    }

    pub fn can_encrypt(&self) -> bool {
        matches!(self.kind, KeyKind::Rsa(_)) && self.ku_encipher != Some(false) && self.valid_now()
    }

    fn key_label(&self) -> String {
        match self.kind {
            KeyKind::Rsa(bits) => format!("RSA {bits}"),
            KeyKind::P256 => "EC P-256".into(),
            KeyKind::P384 => "EC P-384".into(),
            KeyKind::Other => "other".into(),
        }
    }

    pub fn info(&self, trust: &Trust, intermediates: &[&[u8]]) -> CertInfo {
        let (t, detail) = trust.evaluate(self, intermediates, None);
        CertInfo {
            fingerprint: self.fingerprint(),
            name: self.name.clone(),
            subject: self.subject.clone(),
            issuer: self.issuer.clone(),
            emails: self.emails.clone(),
            not_before: iso(self.not_before),
            not_after: iso(self.not_after),
            key: self.key_label(),
            can_encrypt: self.can_encrypt(),
            can_sign: self.ku_sign != Some(false) && self.kind != KeyKind::Other,
            trust: t,
            trust_detail: detail,
            der: B64.encode(&self.der),
        }
    }

    fn issuer_and_serial(&self) -> Vec<u8> {
        asn1::seq(&[&self.issuer_raw, &asn1::tlv(asn1::INTEGER, &self.serial)])
    }

    fn matches_issuer_serial(&self, issuer: &[u8], serial: &[u8]) -> bool {
        self.issuer_raw == issuer && strip_leading_zeros(&self.serial) == strip_leading_zeros(serial)
    }

    fn matches(&self, rid: &Rid<'_>) -> bool {
        match rid {
            Rid::IssuerSerial(i, s) => self.matches_issuer_serial(i, s),
            Rid::Ski(k) => self.ski.as_deref() == Some(&k[..]),
        }
    }
}

fn spki_key(spki: Node<'_>) -> asn1::R<(KeyKind, Vec<u8>)> {
    let k = spki.children()?;
    let alg = at(&k, 0)?.children()?;
    let alg_oid = at(&alg, 0)?.oid()?;
    let bits = at(&k, 1)?;
    let key = bits.content.get(1..).unwrap_or_default().to_vec();
    if oid_is(alg_oid, RSA) {
        let rsa = asn1::read_all(&key)?.children()?;
        let modulus = strip_leading_zeros(at(&rsa, 0)?.content);
        let bits = modulus.len() * 8 - modulus.first().map(|b| b.leading_zeros() as usize).unwrap_or(0);
        Ok((KeyKind::Rsa(bits), key))
    } else if oid_is(alg_oid, EC_PUBLIC_KEY) {
        let curve = at(&alg, 1)?.oid()?;
        let kind = if oid_is(curve, CURVE_P256) {
            KeyKind::P256
        } else if oid_is(curve, CURVE_P384) {
            KeyKind::P384
        } else {
            KeyKind::Other
        };
        Ok((kind, key))
    } else {
        Ok((KeyKind::Other, key))
    }
}

/// Certificates from PEM text, DER, or a certs-only PKCS#7 bundle (.p7c/.p7b).
pub fn certificates_from(input: &[u8]) -> Vec<Cert> {
    let mut out = Vec::new();
    if input.windows(11).any(|w| w == b"-----BEGIN ") {
        for c in rustls_pemfile::certs(&mut &input[..]).flatten() {
            if let Ok(c) = Cert::parse(c.as_ref()) {
                out.push(c);
            }
        }
        if out.is_empty() {
            // A PEM-wrapped PKCS#7 bundle.
            let body: String = String::from_utf8_lossy(input)
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect();
            if let Ok(der) = lenient_b64().decode(body.trim()) {
                out.extend(certs_in_cms(&der));
            }
        }
    } else if let Ok(c) = Cert::parse(input) {
        out.push(c);
    } else {
        out.extend(certs_in_cms(input));
    }
    out.truncate(20);
    out
}

fn certs_in_cms(der: &[u8]) -> Vec<Cert> {
    let Ok((ty, content)) = content_info(der) else {
        return Vec::new();
    };
    if !oid_is(ty, SIGNED_DATA) {
        return Vec::new();
    }
    parse_signed(content)
        .map(|s| s.certs.iter().filter_map(|c| Cert::parse(c).ok()).collect())
        .unwrap_or_default()
}

// ---- trust -----------------------------------------------------------------

/// The trust anchors for e-mail certificates.
pub struct Trust {
    anchors: Vec<TrustAnchor<'static>>,
}

impl Trust {
    pub fn load(extra_file: Option<&str>) -> std::result::Result<Trust, String> {
        let mut pem: Vec<u8> = include_bytes!("roots.pem").to_vec();
        if let Some(path) = extra_file {
            let more = std::fs::read(path).map_err(|e| format!("POSTERN_SMIME_CA_FILE {path}: {e}"))?;
            pem.push(b'\n');
            pem.extend(more);
        }
        let mut anchors = Vec::new();
        for der in rustls_pemfile::certs(&mut pem.as_slice()).flatten() {
            if let Ok(a) = webpki::anchor_from_trusted_cert(&der) {
                anchors.push(a.to_owned());
            }
        }
        if anchors.is_empty() {
            return Err("no S/MIME trust anchors could be read".into());
        }
        Ok(Trust { anchors })
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    fn check(&self, leaf: &[u8], intermediates: &[&[u8]], at: i64) -> std::result::Result<(), webpki::Error> {
        let leaf = CertificateDer::from(leaf);
        let ee = webpki::EndEntityCert::try_from(&leaf)?;
        let inter: Vec<CertificateDer<'_>> = intermediates.iter().map(|c| CertificateDer::from(*c)).collect();
        ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &self.anchors,
            &inter,
            UnixTime::since_unix_epoch(Duration::from_secs(at.max(0) as u64)),
            webpki::KeyUsage::required_if_present(EMAIL_PROTECTION),
            None,
            None,
        )
        .map(|_| ())
    }

    /// trusted | expired | untrusted | invalid, with a sentence for people.
    fn evaluate(&self, cert: &Cert, intermediates: &[&[u8]], signed_at: Option<i64>) -> (&'static str, String) {
        let now = seal::unix_now() as i64;
        match self.check(&cert.der, intermediates, now) {
            Ok(()) => ("trusted", String::new()),
            Err(webpki::Error::CertExpired { .. }) => {
                let then_ok = signed_at
                    .filter(|t| *t <= now)
                    .map(|t| self.check(&cert.der, intermediates, t).is_ok())
                    .unwrap_or(false);
                if then_ok {
                    ("expired", "The certificate was valid when the message was signed and has expired since.".into())
                } else {
                    ("expired", "The certificate has expired.".into())
                }
            }
            Err(webpki::Error::CertNotValidYet { .. }) => ("invalid", "The certificate is not valid yet.".into()),
            Err(webpki::Error::UnknownIssuer) => (
                "untrusted",
                "The certificate was not issued by an authority this server trusts.".into(),
            ),
            Err(e) => ("invalid", format!("The certificate could not be verified ({e:?}).")),
        }
    }
}

// ---- the user's own key ----------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SealedKey {
    v: u8,
    email: String,
    key: String,
    certs: Vec<String>,
}

/// The user's private key and certificate chain, unsealed for one request.
#[derive(Clone)]
pub struct OwnKey {
    pkcs8: Vec<u8>,
    pub cert: Cert,
    chain: Vec<Vec<u8>>,
}

fn context(email: &str) -> String {
    format!("{SEAL_CONTEXT}|{}", email.to_ascii_lowercase())
}

/// Opens a key sealed by [`import`]; `None` if it is not for this address or
/// the server key has changed since.
pub fn open_key(sealer: &Sealer, sealed: &str, email: &str) -> Option<OwnKey> {
    let s: SealedKey = sealer.open(&context(email), sealed)?;
    if s.v != 1 || !s.email.eq_ignore_ascii_case(email) {
        return None;
    }
    let pkcs8 = B64.decode(s.key).ok()?;
    let mut certs = s.certs.iter().filter_map(|c| B64.decode(c).ok());
    let cert = Cert::parse(&certs.next()?).ok()?;
    Some(OwnKey {
        pkcs8,
        cert,
        chain: certs.collect(),
    })
}

pub struct Imported {
    pub sealed: String,
    pub cert: CertInfo,
    pub email_match: bool,
    pub can_decrypt: bool,
}

/// Reads a PKCS#12 file, checks that key and certificate belong together and
/// returns them sealed for `email`. The password is used here and forgotten.
pub fn import(sealer: &Sealer, trust: &Trust, data: &[u8], password: &str, email: &str) -> Result<Imported> {
    let archive = p12_keystore::Pkcs12Archive::from_pkcs12(data, password)
        .map_err(|_| Error::bad("The file could not be opened. Is the password right, and is it a .p12 or .pfx file?"))?;
    let certs: Vec<Cert> = archive
        .certs
        .iter()
        .filter_map(|b| Cert::parse(b.cert.as_der()).ok())
        .collect();
    let rng = SystemRandom::new();
    for bag in &archive.keys {
        let pkcs8 = bag.key.as_der().to_vec();
        let public: Option<(Vec<u8>, &'static str)> = if let Ok(kp) = RsaKeyPair::from_pkcs8(&pkcs8) {
            Some((kp.public().as_ref().to_vec(), "rsa"))
        } else if let Ok(kp) = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng) {
            Some((signature::KeyPair::public_key(&kp).as_ref().to_vec(), "ec"))
        } else if let Ok(kp) = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, &pkcs8, &rng) {
            Some((signature::KeyPair::public_key(&kp).as_ref().to_vec(), "ec"))
        } else {
            None
        };
        let Some((public, kind)) = public else {
            continue;
        };
        let Some(leaf) = certs.iter().find(|c| c.public_key == public) else {
            continue;
        };
        let can_decrypt = kind == "rsa" && {
            use rsa::pkcs8::DecodePrivateKey;
            rsa::PrivateKey::from_pkcs8_der(&pkcs8).is_ok()
        };
        let mut chain: Vec<Vec<u8>> = Vec::new();
        for c in &certs {
            if c.der != leaf.der && !chain.contains(&c.der) && chain.len() < 6 {
                chain.push(c.der.clone());
            }
        }
        let inter: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();
        let info = leaf.info(trust, &inter);
        let email_match = leaf.emails.iter().any(|e| e.eq_ignore_ascii_case(email));
        let mut all = vec![B64.encode(&leaf.der)];
        all.extend(chain.iter().map(|c| B64.encode(c)));
        let sealed = sealer.seal(
            &context(email),
            &SealedKey {
                v: 1,
                email: email.to_ascii_lowercase(),
                key: B64.encode(&pkcs8),
                certs: all,
            },
        );
        return Ok(Imported {
            sealed,
            cert: info,
            email_match,
            can_decrypt,
        });
    }
    if archive.keys.is_empty() {
        return Err(Error::bad("The file holds no private key."));
    }
    Err(Error::bad(
        "No usable key was found: Postern supports RSA keys of 2048 to 4096 bits and EC keys on P-256 or P-384, each with its certificate in the file.",
    ))
}

impl OwnKey {
    fn hash(&self) -> Hash {
        if self.cert.kind == KeyKind::P384 { Hash::Sha384 } else { Hash::Sha256 }
    }

    /// Signs `data`; returns the signature and its AlgorithmIdentifier.
    fn sign(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let rng = SystemRandom::new();
        let fail = |_| Error::Internal("signing failed".into());
        match self.cert.kind {
            KeyKind::Rsa(_) => {
                let kp = RsaKeyPair::from_pkcs8(&self.pkcs8).map_err(|_| Error::Internal("unusable RSA key".into()))?;
                let mut sig = vec![0u8; kp.public().modulus_len()];
                kp.sign(&signature::RSA_PKCS1_SHA256, &rng, data, &mut sig).map_err(fail)?;
                Ok((sig, asn1::alg(RSA, true)))
            }
            KeyKind::P256 | KeyKind::P384 => {
                let (alg, oid) = if self.cert.kind == KeyKind::P256 {
                    (&signature::ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_SHA256)
                } else {
                    (&signature::ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_SHA384)
                };
                let kp = EcdsaKeyPair::from_pkcs8(alg, &self.pkcs8, &rng)
                    .map_err(|_| Error::Internal("unusable EC key".into()))?;
                let sig = kp.sign(&rng, data).map_err(fail)?;
                Ok((sig.as_ref().to_vec(), asn1::alg(oid, false)))
            }
            KeyKind::Other => Err(Error::bad("this key type cannot sign")),
        }
    }
}

// ---- CMS parsing -----------------------------------------------------------

fn content_info(der: &[u8]) -> asn1::R<(&[u8], Node<'_>)> {
    let top = asn1::read_all(der)?.expect(SEQUENCE)?;
    let k = top.children()?;
    let ty = at(&k, 0)?.oid()?;
    let wrapped = at(&k, 1)?.expect(0xa0)?;
    let content = at(&wrapped.children()?, 0)?;
    Ok((ty, content))
}

enum Rid<'a> {
    IssuerSerial(&'a [u8], &'a [u8]),
    Ski(Cow<'a, [u8]>),
}

fn rid(n: Node<'_>) -> asn1::R<Rid<'_>> {
    match n.tag {
        SEQUENCE => {
            let k = n.children()?;
            Ok(Rid::IssuerSerial(at(&k, 0)?.raw, at(&k, 1)?.expect(asn1::INTEGER)?.content))
        }
        0x80 | 0xa0 => Ok(Rid::Ski(n.octets()?)),
        _ => Err(asn1::Asn1Error("unknown identifier")),
    }
}

struct Signed<'a> {
    econtent_type: &'a [u8],
    econtent: Option<Vec<u8>>,
    certs: Vec<&'a [u8]>,
    signers: Vec<Signer<'a>>,
}

struct Signer<'a> {
    sid: Rid<'a>,
    digest: &'a [u8],
    attrs: Option<Node<'a>>,
    sig_alg: &'a [u8],
    sig_params: Option<Node<'a>>,
    signature: Vec<u8>,
}

fn octets_of(n: Node<'_>) -> asn1::R<Cow<'_, [u8]>> {
    match n.tag {
        OCTET_STRING | OCTET_STRING_C => n.octets(),
        _ => Err(asn1::Asn1Error("expected an octet string")),
    }
}

fn parse_signed(n: Node<'_>) -> asn1::R<Signed<'_>> {
    let k = n.expect(SEQUENCE)?.children()?;
    let mut i = 2; // version, digestAlgorithms
    let encap = at(&k, i)?.expect(SEQUENCE)?.children()?;
    i += 1;
    let econtent_type = at(&encap, 0)?.oid()?;
    let econtent = match encap.get(1) {
        Some(e) if e.tag == 0xa0 => Some(octets_of(at(&e.children()?, 0)?)?.into_owned()),
        _ => None,
    };
    let mut certs = Vec::new();
    if k.get(i).map(|x| x.tag) == Some(0xa0) {
        for c in k[i].children()? {
            if c.tag == SEQUENCE {
                certs.push(c.raw);
            }
        }
        i += 1;
    }
    if k.get(i).map(|x| x.tag) == Some(0xa1) {
        i += 1;
    }
    let mut signers = Vec::new();
    for s in at(&k, i)?.expect(SET)?.children()? {
        let f = s.expect(SEQUENCE)?.children()?;
        let sid = rid(at(&f, 1)?)?;
        let digest = at(&at(&f, 2)?.children()?, 0)?.oid()?;
        let mut j = 3;
        let attrs = if at(&f, j)?.tag == 0xa0 {
            j += 1;
            Some(f[j - 1])
        } else {
            None
        };
        let alg = at(&f, j)?.expect(SEQUENCE)?.children()?;
        let signature = octets_of(at(&f, j + 1)?)?.into_owned();
        signers.push(Signer {
            sid,
            digest,
            attrs,
            sig_alg: at(&alg, 0)?.oid()?,
            sig_params: alg.get(1).copied(),
            signature,
        });
    }
    Ok(Signed {
        econtent_type,
        econtent,
        certs,
        signers,
    })
}

// ---- verifying -------------------------------------------------------------

/// The result of checking a signature, as the browser gets it.
#[derive(Serialize, Clone, Debug)]
pub struct SignatureReport {
    /// valid | invalid | unsupported | error
    pub status: &'static str,
    pub detail: String,
    pub signer: Option<CertInfo>,
    pub signer_matches_from: bool,
    /// trusted | expired | untrusted | invalid, or empty when not checked
    pub trust: &'static str,
    pub trust_detail: String,
    pub signed_at: Option<String>,
    pub weak: bool,
}

impl SignatureReport {
    fn fail(status: &'static str, detail: impl Into<String>) -> Self {
        SignatureReport {
            status,
            detail: detail.into(),
            signer: None,
            signer_matches_from: false,
            trust: "",
            trust_detail: String::new(),
            signed_at: None,
            weak: false,
        }
    }
}

enum SigErr {
    Unsupported(String),
    Bad,
}

fn pss_hash(params: Option<Node<'_>>) -> Option<Hash> {
    let Some(p) = params else { return Some(Hash::Sha1) };
    for f in p.children().ok()? {
        if f.tag == 0xa0 {
            let alg = at(&f.children().ok()?, 0).ok()?;
            return Hash::from_oid(at(&alg.children().ok()?, 0).ok()?.oid().ok()?);
        }
    }
    Some(Hash::Sha1)
}

fn verify_signature(cert: &Cert, digest: Hash, sig_alg: &[u8], params: Option<Node<'_>>, data: &[u8], sig: &[u8]) -> std::result::Result<bool, SigErr> {
    use signature as s;
    let mut weak = digest == Hash::Sha1;
    let rsa_hash = if oid_is(sig_alg, RSA) {
        Some(digest)
    } else if oid_is(sig_alg, RSA_SHA1) {
        Some(Hash::Sha1)
    } else if oid_is(sig_alg, RSA_SHA256) {
        Some(Hash::Sha256)
    } else if oid_is(sig_alg, RSA_SHA384) {
        Some(Hash::Sha384)
    } else if oid_is(sig_alg, RSA_SHA512) {
        Some(Hash::Sha512)
    } else {
        None
    };
    let alg: &'static dyn VerificationAlgorithm = if let Some(h) = rsa_hash {
        let KeyKind::Rsa(bits) = cert.kind else {
            return Err(SigErr::Unsupported("the signature algorithm does not fit the key".into()));
        };
        let strong = bits >= 2048;
        weak |= !strong || h == Hash::Sha1;
        match (h, strong) {
            (Hash::Sha1, _) => &s::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            (Hash::Sha256, true) => &s::RSA_PKCS1_2048_8192_SHA256,
            (Hash::Sha256, false) => &s::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            (Hash::Sha384, _) => &s::RSA_PKCS1_2048_8192_SHA384,
            (Hash::Sha512, true) => &s::RSA_PKCS1_2048_8192_SHA512,
            (Hash::Sha512, false) => &s::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
        }
    } else if oid_is(sig_alg, RSA_PSS) {
        match pss_hash(params) {
            Some(Hash::Sha256) => &s::RSA_PSS_2048_8192_SHA256,
            Some(Hash::Sha384) => &s::RSA_PSS_2048_8192_SHA384,
            Some(Hash::Sha512) => &s::RSA_PSS_2048_8192_SHA512,
            _ => return Err(SigErr::Unsupported("RSA-PSS with this hash".into())),
        }
    } else if oid_is(sig_alg, ECDSA_SHA256) || oid_is(sig_alg, ECDSA_SHA384) || oid_is(sig_alg, ECDSA_SHA512) || oid_is(sig_alg, EC_PUBLIC_KEY) {
        let h = if oid_is(sig_alg, ECDSA_SHA256) {
            Hash::Sha256
        } else if oid_is(sig_alg, ECDSA_SHA384) {
            Hash::Sha384
        } else if oid_is(sig_alg, ECDSA_SHA512) {
            Hash::Sha512
        } else {
            digest
        };
        match (cert.kind, h) {
            (KeyKind::P256, Hash::Sha256) => &s::ECDSA_P256_SHA256_ASN1,
            (KeyKind::P256, Hash::Sha384) => &s::ECDSA_P256_SHA384_ASN1,
            (KeyKind::P384, Hash::Sha256) => &s::ECDSA_P384_SHA256_ASN1,
            (KeyKind::P384, Hash::Sha384) => &s::ECDSA_P384_SHA384_ASN1,
            _ => return Err(SigErr::Unsupported("this ECDSA curve and hash".into())),
        }
    } else {
        return Err(SigErr::Unsupported("this signature algorithm".into()));
    };
    UnparsedPublicKey::new(alg, &cert.public_key)
        .verify(data, sig)
        .map(|_| weak)
        .map_err(|_| SigErr::Bad)
}

fn parse_time(n: Node<'_>) -> Option<i64> {
    let s = std::str::from_utf8(n.content).ok()?;
    let (fmt, s) = match n.tag {
        asn1::UTC_TIME => {
            let yy: i32 = s.get(0..2)?.parse().ok()?;
            let century = if yy >= 50 { "19" } else { "20" };
            ("%Y%m%d%H%M%SZ", format!("{century}{s}"))
        }
        asn1::GENERALIZED_TIME => ("%Y%m%d%H%M%SZ", s.to_string()),
        _ => return None,
    };
    chrono::NaiveDateTime::parse_from_str(&s, fmt).ok().map(|d| d.and_utc().timestamp())
}

/// Checks a SignedData. `detached` is the signed content of a
/// multipart/signed message; without it the content must be inside.
/// Returns the report and the content, for showing.
fn verify(trust: &Trust, cms: &[u8], detached: Option<&[u8]>, from: &[String]) -> (SignatureReport, Option<Vec<u8>>) {
    let Ok((ty, content)) = content_info(cms) else {
        return (SignatureReport::fail("error", "The signature could not be read."), None);
    };
    if !oid_is(ty, SIGNED_DATA) {
        return (SignatureReport::fail("error", "The signature part holds something else."), None);
    }
    let signed = match parse_signed(content) {
        Ok(s) => s,
        Err(_) => return (SignatureReport::fail("error", "The signature could not be read."), None),
    };
    let body: Vec<u8> = match (detached, &signed.econtent) {
        (Some(d), _) => d.to_vec(),
        (None, Some(e)) => e.clone(),
        (None, None) => return (SignatureReport::fail("error", "The signed content is missing."), None),
    };
    let shown = Some(body.clone());
    let Some(signer) = signed.signers.first() else {
        return (SignatureReport::fail("error", "The message carries no signature."), shown);
    };
    let certs: Vec<Cert> = signed.certs.iter().filter_map(|c| Cert::parse(c).ok()).collect();
    let Some(cert) = certs.iter().find(|c| c.matches(&signer.sid)) else {
        return (
            SignatureReport::fail("error", "The signer's certificate is not included, so the signature cannot be checked."),
            shown,
        );
    };
    let Some(digest) = Hash::from_oid(signer.digest) else {
        return (SignatureReport::fail("unsupported", "The signature uses a hash Postern does not support."), shown);
    };
    let mut signed_at = None;
    let data: Cow<'_, [u8]> = match signer.attrs {
        Some(attrs) => {
            let mut md = None;
            let mut ct = None;
            for a in attrs.children().unwrap_or_default() {
                let Ok(f) = a.children() else { continue };
                let (Some(t), Some(vals)) = (f.first(), f.get(1)) else { continue };
                let Ok(t) = t.oid() else { continue };
                let first = vals.children().ok().and_then(|v| v.first().copied());
                if oid_is(t, ATTR_MESSAGE_DIGEST) {
                    md = first.and_then(|v| v.octets().ok()).map(|c| c.into_owned());
                } else if oid_is(t, ATTR_CONTENT_TYPE) {
                    ct = first.and_then(|v| v.oid().ok());
                } else if oid_is(t, ATTR_SIGNING_TIME) {
                    signed_at = first.and_then(parse_time);
                }
            }
            if md.as_deref() != Some(&digest.digest(&body)[..]) {
                let mut r = SignatureReport::fail("invalid", "The message was changed after it was signed.");
                r.signer = Some(cert.info(trust, &[]));
                return (r, shown);
            }
            if ct != Some(signed.econtent_type) {
                return (SignatureReport::fail("invalid", "The signed attributes do not match the content."), shown);
            }
            let mut d = attrs.raw.to_vec();
            d[0] = SET;
            Cow::Owned(d)
        }
        None => Cow::Borrowed(&body[..]),
    };
    let intermediates: Vec<&[u8]> = signed
        .certs
        .iter()
        .copied()
        .filter(|c| *c != cert.der.as_slice())
        .collect();
    let info = cert.info(trust, &intermediates);
    let matches = from.iter().any(|f| cert.emails.iter().any(|e| e.eq_ignore_ascii_case(f)));
    match verify_signature(cert, digest, signer.sig_alg, signer.sig_params, &data, &signer.signature) {
        Ok(weak) => {
            let (t, detail) = trust.evaluate(cert, &intermediates, signed_at);
            (
                SignatureReport {
                    status: "valid",
                    detail: String::new(),
                    signer: Some(info),
                    signer_matches_from: matches,
                    trust: t,
                    trust_detail: detail,
                    signed_at: signed_at.map(iso),
                    weak,
                },
                shown,
            )
        }
        Err(SigErr::Bad) => {
            let mut r = SignatureReport::fail("invalid", "The signature does not match the message. It may have been changed.");
            r.signer = Some(info);
            (r, shown)
        }
        Err(SigErr::Unsupported(what)) => {
            let mut r = SignatureReport::fail("unsupported", format!("Postern cannot check {what}."));
            r.signer = Some(info);
            (r, shown)
        }
    }
}

// ---- decrypting ------------------------------------------------------------

#[derive(Serialize, Clone, Debug)]
pub struct EncryptionReport {
    /// decrypted | no_key | not_for_you | unsupported | failed
    pub status: &'static str,
    pub detail: String,
    pub algorithm: String,
}

impl EncryptionReport {
    fn new(status: &'static str, detail: impl Into<String>) -> Self {
        EncryptionReport {
            status,
            detail: detail.into(),
            algorithm: String::new(),
        }
    }
}

fn cbc_decrypt(alg: &str, key: &[u8], iv: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    match alg {
        AES128_CBC => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv).ok()?.decrypt_padded_vec::<Pkcs7>(ct).ok(),
        AES192_CBC => cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv).ok()?.decrypt_padded_vec::<Pkcs7>(ct).ok(),
        AES256_CBC => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).ok()?.decrypt_padded_vec::<Pkcs7>(ct).ok(),
        DES_EDE3_CBC => cbc::Decryptor::<des::TdesEde3>::new_from_slices(key, iv).ok()?.decrypt_padded_vec::<Pkcs7>(ct).ok(),
        _ => None,
    }
}

fn decrypt(key: &OwnKey, cms: &[u8]) -> std::result::Result<(Vec<u8>, String), EncryptionReport> {
    let failed = || EncryptionReport::new("failed", "The message could not be decrypted. It may be damaged.");
    let (ty, content) = content_info(cms).map_err(|_| failed())?;
    if oid_is(ty, AUTH_ENVELOPED_DATA) {
        return Err(EncryptionReport::new("unsupported", "This message uses AES-GCM (AuthEnvelopedData), which Postern cannot decrypt yet."));
    }
    if !oid_is(ty, ENVELOPED_DATA) {
        return Err(failed());
    }
    let parts = (|| -> asn1::R<_> {
        let k = content.expect(SEQUENCE)?.children()?;
        let mut i = 1;
        if at(&k, i)?.tag == 0xa0 {
            i += 1;
        }
        let ris = at(&k, i)?.expect(SET)?.children()?;
        let eci = at(&k, i + 1)?.expect(SEQUENCE)?.children()?;
        let calg = at(&eci, 1)?.expect(SEQUENCE)?.children()?;
        let coid = at(&calg, 0)?.oid()?;
        let iv = calg.get(1).map(|n| octets_of(*n)).transpose()?.map(|c| c.into_owned());
        let ct = match eci.get(2) {
            Some(n) if n.tag == 0x80 || n.tag == 0xa0 => n.octets()?.into_owned(),
            _ => return Err(asn1::Asn1Error("no encrypted content")),
        };
        Ok((ris, coid, iv, ct))
    })();
    let (ris, coid, iv, ct) = parts.map_err(|_| failed())?;
    let (alg, key_len, name) = if oid_is(coid, AES256_CBC) {
        (AES256_CBC, 32, "AES-256-CBC")
    } else if oid_is(coid, AES192_CBC) {
        (AES192_CBC, 24, "AES-192-CBC")
    } else if oid_is(coid, AES128_CBC) {
        (AES128_CBC, 16, "AES-128-CBC")
    } else if oid_is(coid, DES_EDE3_CBC) {
        (DES_EDE3_CBC, 24, "3DES-CBC")
    } else {
        return Err(EncryptionReport::new("unsupported", "The message uses a cipher Postern does not support."));
    };
    let iv = iv.ok_or_else(failed)?;

    let mut mine: Option<(Node<'_>, Vec<u8>)> = None;
    let mut key_agree = false;
    for ri in &ris {
        if ri.tag == 0xa1 {
            key_agree = true;
            continue;
        }
        if ri.tag != SEQUENCE {
            continue;
        }
        let Ok(f) = ri.children() else { continue };
        let (Some(r), Some(alg), Some(ek)) = (f.get(1), f.get(2), f.get(3)) else { continue };
        if let Ok(r) = rid(*r) {
            if key.cert.matches(&r) {
                if let Ok(ek) = octets_of(*ek) {
                    mine = Some((*alg, ek.into_owned()));
                    break;
                }
            }
        }
    }
    let Some((kalg, ek)) = mine else {
        if key_agree && !matches!(key.cert.kind, KeyKind::Rsa(_)) {
            return Err(EncryptionReport::new("unsupported", "This message was encrypted for an EC key, which Postern cannot decrypt yet."));
        }
        return Err(EncryptionReport::new("not_for_you", "This message was not encrypted for your certificate."));
    };
    let priv_key = {
        use rsa::pkcs8::DecodePrivateKey;
        rsa::PrivateKey::from_pkcs8_der(&key.pkcs8).map_err(|_| {
            EncryptionReport::new("unsupported", "Your key cannot decrypt (only RSA keys can).")
        })?
    };
    let kalg_parts = kalg.children().unwrap_or_default();
    let koid = kalg_parts.first().and_then(|n| n.oid().ok()).unwrap_or_default();
    let unwrapped = if oid_is(koid, RSA) {
        priv_key.pkcs1v15_decrypt(&ek).ok()
    } else if oid_is(koid, RSA_OAEP) {
        // The hash is the first optional field of RSAES-OAEP-params; SHA-1 by default.
        let h = kalg_parts
            .get(1)
            .and_then(|p| p.children().ok())
            .and_then(|f| f.into_iter().find(|x| x.tag == 0xa0))
            .and_then(|x| x.children().ok()?.first().copied())
            .and_then(|a| Hash::from_oid(a.children().ok()?.first()?.oid().ok()?))
            .unwrap_or(Hash::Sha1);
        match h {
            Hash::Sha1 => priv_key.oaep_decrypt::<sha1::Sha1>(&ek).ok(),
            Hash::Sha256 => priv_key.oaep_decrypt::<sha2::Sha256>(&ek).ok(),
            Hash::Sha384 => priv_key.oaep_decrypt::<sha2::Sha384>(&ek).ok(),
            Hash::Sha512 => priv_key.oaep_decrypt::<sha2::Sha512>(&ek).ok(),
        }
    } else {
        return Err(EncryptionReport::new("unsupported", "The message uses a key transport Postern does not support."));
    };
    // A failed unwrap carries on with a random key, so that a damaged or
    // forged key and a damaged body end in the same place (RFC 3218).
    let unwrap_ok = matches!(&unwrapped, Some(k) if k.len() == key_len);
    let cek = match unwrapped {
        Some(k) if k.len() == key_len => k,
        _ => {
            let mut r = vec![0u8; key_len];
            let _ = SystemRandom::new().fill(&mut r);
            r
        }
    };
    let plain = cbc_decrypt(alg, &cek, &iv, &ct);
    match plain {
        Some(p) if unwrap_ok => Ok((p, name.to_string())),
        _ => Err(failed()),
    }
}

// ---- building --------------------------------------------------------------

fn utc_time(ts: i64) -> Vec<u8> {
    let d = chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default();
    asn1::tlv(asn1::UTC_TIME, d.format("%y%m%d%H%M%SZ").to_string().as_bytes())
}

fn attribute(oid: &str, value: Vec<u8>) -> Vec<u8> {
    asn1::seq(&[&asn1::oid_tlv(oid), &asn1::set_of(vec![value])])
}

/// A detached SignedData over `content`.
fn signed_data(key: &OwnKey, content: &[u8]) -> Result<Vec<u8>> {
    let hash = key.hash();
    let ias = key.cert.issuer_and_serial();
    let caps = asn1::seq(&[
        &asn1::alg(AES256_CBC, false),
        &asn1::alg(AES192_CBC, false),
        &asn1::alg(AES128_CBC, false),
        &asn1::alg(DES_EDE3_CBC, false),
    ]);
    let attrs = asn1::set_of(vec![
        attribute(ATTR_CONTENT_TYPE, asn1::oid_tlv(DATA)),
        attribute(ATTR_SIGNING_TIME, utc_time(seal::unix_now() as i64)),
        attribute(ATTR_MESSAGE_DIGEST, asn1::octet_string(&hash.digest(content))),
        attribute(ATTR_SMIME_CAPS, caps),
        attribute(ATTR_ENC_KEY_PREF, asn1::retag(ias.clone(), 0xa0)),
        attribute(ATTR_MS_ENC_KEY_PREF, ias.clone()),
    ]);
    let (sig, sig_alg) = key.sign(&attrs)?;
    let digest_alg = asn1::alg(hash.oid(), false);
    let signer = asn1::seq(&[
        &asn1::small_int_tlv(1),
        &ias,
        &digest_alg,
        &asn1::retag(attrs, 0xa0),
        &sig_alg,
        &asn1::octet_string(&sig),
    ]);
    let mut certs = vec![key.cert.der.clone()];
    certs.extend(key.chain.iter().cloned());
    let sd = asn1::seq(&[
        &asn1::small_int_tlv(1),
        &asn1::set_of(vec![digest_alg]),
        &asn1::seq(&[&asn1::oid_tlv(DATA)]),
        &asn1::retag(asn1::set_of(certs), 0xa0),
        &asn1::set_of(vec![signer]),
    ]);
    Ok(asn1::seq(&[&asn1::oid_tlv(SIGNED_DATA), &asn1::tlv(0xa0, &sd)]))
}

/// An EnvelopedData of `content` for the given certificates (RSA, AES-256-CBC).
fn enveloped_data(content: &[u8], recipients: &[&Cert]) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut cek = [0u8; 32];
    let mut iv = [0u8; 16];
    rng.fill(&mut cek).map_err(|_| Error::Internal("random".into()))?;
    rng.fill(&mut iv).map_err(|_| Error::Internal("random".into()))?;
    let ct = cbc::Encryptor::<aes::Aes256>::new_from_slices(&cek, &iv)
        .map_err(|_| Error::Internal("cipher".into()))?
        .encrypt_padded_vec::<Pkcs7>(content);
    let mut ris = Vec::new();
    for r in recipients {
        if !matches!(r.kind, KeyKind::Rsa(_)) {
            return Err(Error::bad(format!(
                "The certificate for {} has an EC key. Encrypting to EC keys is not supported yet.",
                r.emails.first().map(String::as_str).unwrap_or(&r.name)
            )));
        }
        let pk = {
            use rsa::pkcs1::DecodeRsaPublicKey;
            rsa::PublicKey::from_pkcs1_der(&r.public_key).map_err(|_| Error::bad("unusable recipient key"))?
        };
        let ek = pk.pkcs1v15_encrypt(&cek).map_err(|_| Error::Internal("RSA encryption failed".into()))?;
        ris.push(asn1::seq(&[
            &asn1::small_int_tlv(0),
            &r.issuer_and_serial(),
            &asn1::alg(RSA, true),
            &asn1::octet_string(&ek),
        ]));
    }
    let eci = asn1::seq(&[
        &asn1::oid_tlv(DATA),
        &asn1::seq(&[&asn1::oid_tlv(AES256_CBC), &asn1::octet_string(&iv)]),
        &asn1::tlv(0x80, &ct),
    ]);
    let env = asn1::seq(&[&asn1::small_int_tlv(0), &asn1::set_of(ris), &eci]);
    Ok(asn1::seq(&[&asn1::oid_tlv(ENVELOPED_DATA), &asn1::tlv(0xa0, &env)]))
}

fn b64_lines(data: &[u8]) -> Vec<u8> {
    let s = B64.encode(data);
    let mut out = Vec::with_capacity(s.len() + s.len() / 76 * 2 + 2);
    for chunk in s.as_bytes().chunks(76) {
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Wraps a MIME entity (headers and body, CRLF line ends) into a
/// multipart/signed entity with a detached signature.
pub fn signed_entity(key: &OwnKey, entity: &[u8]) -> Result<Vec<u8>> {
    let cms = signed_data(key, entity)?;
    let boundary = loop {
        let b = format!("----=_postern_{}", seal::hex(&seal::random_bytes::<12>()));
        if !entity.windows(b.len()).any(|w| w == b.as_bytes()) {
            break b;
        }
    };
    let mut out = format!(
        "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\";\r\n micalg={}; boundary=\"{boundary}\"\r\n\r\n\
This is a cryptographically signed message in MIME format.\r\n\r\n--{boundary}\r\n",
        key.hash().micalg()
    )
    .into_bytes();
    out.extend_from_slice(entity);
    out.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n\
Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"smime.p7s\"\r\n\
Content-Description: S/MIME Cryptographic Signature\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend(b64_lines(&cms));
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(out)
}

/// Encrypts a MIME entity for the given certificates.
pub fn enveloped_entity(entity: &[u8], recipients: &[&Cert]) -> Result<Vec<u8>> {
    let cms = enveloped_data(entity, recipients)?;
    let mut out = b"Content-Type: application/pkcs7-mime; smime-type=enveloped-data;\r\n name=\"smime.p7m\"\r\n\
Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"smime.p7m\"\r\n\
Content-Description: S/MIME Encrypted Message\r\n\r\n"
        .to_vec();
    out.extend(b64_lines(&cms));
    Ok(out)
}

/// Splits a message we built into the header fields that stay outside and
/// the MIME entity (the Content-* fields with the body).
pub fn split_message(msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (head, body) = split_entity(msg);
    let mut outer = Vec::new();
    let mut entity = Vec::new();
    let mut field: Vec<u8> = Vec::new();
    let flush = |field: &mut Vec<u8>, outer: &mut Vec<u8>, entity: &mut Vec<u8>| {
        if field.is_empty() {
            return;
        }
        let name = field.split(|b| *b == b':').next().unwrap_or_default().to_ascii_lowercase();
        if name.starts_with(b"content-") {
            entity.extend_from_slice(field);
        } else {
            outer.extend_from_slice(field);
        }
        field.clear();
    };
    for line in head.split_inclusive(|b| *b == b'\n') {
        if !matches!(line.first(), Some(b' ' | b'\t')) {
            flush(&mut field, &mut outer, &mut entity);
        }
        field.extend_from_slice(line);
        if !line.ends_with(b"\n") {
            field.extend_from_slice(b"\r\n");
        }
    }
    flush(&mut field, &mut outer, &mut entity);
    if entity.is_empty() {
        entity.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
    }
    entity.extend_from_slice(b"\r\n");
    entity.extend_from_slice(body);
    (outer, entity)
}

/// The header fields in `head` without those named `name`.
pub fn without_field(head: &[u8], name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len());
    let mut skipping = false;
    for line in head.split_inclusive(|b| *b == b'\n') {
        if !matches!(line.first(), Some(b' ' | b'\t')) {
            let field = line.split(|b| *b == b':').next().unwrap_or_default();
            skipping = field.eq_ignore_ascii_case(name.as_bytes());
        }
        if !skipping {
            out.extend_from_slice(line);
        }
    }
    out
}

// ---- reading messages ------------------------------------------------------

/// The header block (without the blank line) and the body of an entity.
fn split_entity(b: &[u8]) -> (&[u8], &[u8]) {
    if b.starts_with(b"\r\n") {
        return (&[], &b[2..]);
    }
    if b.starts_with(b"\n") {
        return (&[], &b[1..]);
    }
    let crlf = b.windows(4).position(|w| w == b"\r\n\r\n");
    let lf = b.windows(2).position(|w| w == b"\n\n");
    match (crlf, lf) {
        (Some(c), Some(l)) if l < c => (&b[..l + 1], &b[l + 2..]),
        (Some(c), _) => (&b[..c + 2], &b[c + 4..]),
        (None, Some(l)) => (&b[..l + 1], &b[l + 2..]),
        (None, None) => (b, &[]),
    }
}

struct EntityType {
    mime: String,
    params: Vec<(String, String)>,
    encoding: String,
}

impl EntityType {
    fn param(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

fn entity_type(head: &[u8]) -> Option<EntityType> {
    let mut buf = head.to_vec();
    buf.extend_from_slice(b"\r\n\r\n");
    let m = MessageParser::default().parse(&buf)?;
    let ct = m.content_type()?;
    let mime = match &ct.c_subtype {
        Some(s) => format!("{}/{}", ct.c_type, s),
        None => ct.c_type.to_string(),
    }
    .to_ascii_lowercase();
    let params = ct
        .attributes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|a| (a.name.to_ascii_lowercase(), a.value.to_string()))
        .collect();
    let encoding = m.content_transfer_encoding().unwrap_or("7bit").trim().to_ascii_lowercase();
    Some(EntityType { mime, params, encoding })
}

fn lenient_b64() -> GeneralPurpose {
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
}

fn decode_body(t: &EntityType, body: &[u8]) -> Option<Vec<u8>> {
    if t.encoding == "base64" {
        let clean: Vec<u8> = body.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
        lenient_b64().decode(clean).ok()
    } else {
        Some(body.to_vec())
    }
}

/// The two parts of a multipart/signed body: the signed entity, byte for
/// byte, and the signature entity.
fn signed_parts<'a>(body: &'a [u8], boundary: &str) -> Option<(&'a [u8], &'a [u8])> {
    let delim = format!("--{boundary}");
    let mut lines: Vec<(usize, usize)> = Vec::new(); // (line start, start of next line)
    let mut start = 0;
    while start < body.len() {
        let end = body[start..].iter().position(|b| *b == b'\n').map(|p| start + p + 1).unwrap_or(body.len());
        let line = &body[start..end];
        let trimmed = line.strip_suffix(b"\n").unwrap_or(line);
        let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
        if let Some(rest) = trimmed.strip_prefix(delim.as_bytes()) {
            let rest = rest.strip_prefix(b"--").unwrap_or(rest);
            if rest.iter().all(|b| *b == b' ' || *b == b'\t') {
                lines.push((start, end));
                if lines.len() == 3 {
                    break;
                }
            }
        }
        start = end;
    }
    if lines.len() < 3 {
        return None;
    }
    let part = |from: usize, to_line: usize| -> &'a [u8] {
        let mut to = to_line;
        if to >= 1 && body[to - 1] == b'\n' {
            to -= 1;
            if to >= 1 && body[to - 1] == b'\r' {
                to -= 1;
            }
        }
        &body[from..to.max(from)]
    };
    Some((part(lines[0].1, lines[1].0), part(lines[1].1, lines[2].0)))
}

/// Line ends as CRLF, which is what the signature was made over.
fn canonical(b: &[u8]) -> Cow<'_, [u8]> {
    let bare = b.iter().enumerate().any(|(i, c)| *c == b'\n' && (i == 0 || b[i - 1] != b'\r'));
    if !bare {
        return Cow::Borrowed(b);
    }
    let mut out = Vec::with_capacity(b.len() + b.len() / 40);
    for (i, c) in b.iter().enumerate() {
        if *c == b'\n' && (i == 0 || b[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(*c);
    }
    Cow::Owned(out)
}

#[derive(Serialize, Default, Clone, Debug)]
pub struct Security {
    pub signed: Option<SignatureReport>,
    pub encrypted: Option<EncryptionReport>,
}

pub struct Unwrapped {
    /// The entity to show instead of the message body, when there is one.
    pub inner: Option<Vec<u8>>,
    pub security: Security,
}

enum Layer {
    Enveloped,
    Opaque,
    Detached(String),
    Plain,
}

fn layer(t: &EntityType, body: &[u8]) -> Layer {
    match t.mime.as_str() {
        "application/pkcs7-mime" | "application/x-pkcs7-mime" => {
            match t.param("smime-type").map(str::to_ascii_lowercase).as_deref() {
                Some("signed-data") => Layer::Opaque,
                Some("enveloped-data") | Some("authenveloped-data") => Layer::Enveloped,
                _ => {
                    // No usable smime-type: look at what is inside.
                    let der = decode_body(t, body).unwrap_or_default();
                    match content_info(&der) {
                        Ok((ty, _)) if oid_is(ty, SIGNED_DATA) => Layer::Opaque,
                        _ => Layer::Enveloped,
                    }
                }
            }
        }
        "multipart/signed" => {
            let proto = t.param("protocol").unwrap_or_default().to_ascii_lowercase();
            match t.param("boundary") {
                Some(b) if proto == "application/pkcs7-signature" || proto == "application/x-pkcs7-signature" => {
                    Layer::Detached(b.to_string())
                }
                _ => Layer::Plain,
            }
        }
        _ => Layer::Plain,
    }
}

/// Whether the top level of a message is S/MIME, and if so whether encrypted.
pub fn kind_of(raw: &[u8]) -> Option<&'static str> {
    let (head, body) = split_entity(raw);
    let t = entity_type(head)?;
    match layer(&t, body) {
        Layer::Enveloped => Some("encrypted"),
        Layer::Opaque | Layer::Detached(_) => Some("signed"),
        Layer::Plain => None,
    }
}

/// Verifies and decrypts the S/MIME layers at the top of a message.
/// `from` are the sender addresses the signer must match.
pub fn unwrap(raw: &[u8], from: &[String], key: Option<&OwnKey>, trust: &Trust) -> Unwrapped {
    let mut cur: Cow<'_, [u8]> = Cow::Borrowed(raw);
    let mut changed = false;
    let mut sec = Security::default();
    for _ in 0..4 {
        let (head, body) = split_entity(&cur);
        let Some(t) = entity_type(head) else { break };
        match layer(&t, body) {
            Layer::Plain => break,
            Layer::Enveloped => {
                if sec.encrypted.is_some() {
                    break;
                }
                let Some(key) = key else {
                    sec.encrypted = Some(EncryptionReport::new("no_key", "This message is encrypted. Import your S/MIME key on this device to read it."));
                    break;
                };
                let Some(der) = decode_body(&t, body) else {
                    sec.encrypted = Some(EncryptionReport::new("failed", "The encrypted part could not be read."));
                    break;
                };
                match decrypt(key, &der) {
                    Ok((plain, alg)) => {
                        sec.encrypted = Some(EncryptionReport {
                            status: "decrypted",
                            detail: String::new(),
                            algorithm: alg,
                        });
                        cur = Cow::Owned(plain);
                        changed = true;
                    }
                    Err(report) => {
                        sec.encrypted = Some(report);
                        break;
                    }
                }
            }
            Layer::Opaque => {
                let Some(der) = decode_body(&t, body) else { break };
                let (report, content) = verify(trust, &der, None, from);
                if sec.signed.is_none() {
                    sec.signed = Some(report);
                }
                match content {
                    Some(c) => {
                        cur = Cow::Owned(c);
                        changed = true;
                    }
                    None => break,
                }
            }
            Layer::Detached(boundary) => {
                let Some((content, sig)) = signed_parts(body, &boundary) else { break };
                let content = canonical(content).into_owned();
                let (sh, sb) = split_entity(sig);
                let der = entity_type(sh).and_then(|st| decode_body(&st, sb)).unwrap_or_default();
                let (report, _) = verify(trust, &der, Some(&content), from);
                if sec.signed.is_none() {
                    sec.signed = Some(report);
                }
                cur = Cow::Owned(content);
                changed = true;
            }
        }
    }
    Unwrapped {
        inner: changed.then(|| cur.into_owned()),
        security: sec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_load() {
        let t = Trust::load(None).unwrap();
        assert!(t.len() > 50, "{}", t.len());
    }

    #[test]
    fn splits_a_built_message() {
        let msg = b"From: a@b\r\nSubject: x\r\nMIME-Version: 1.0\r\nContent-Type: text/plain;\r\n charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\nMessage-ID: <1@b>\r\n\r\nhello\r\n";
        let (outer, entity) = split_message(msg);
        assert_eq!(outer, b"From: a@b\r\nSubject: x\r\nMIME-Version: 1.0\r\nMessage-ID: <1@b>\r\n");
        assert_eq!(entity, b"Content-Type: text/plain;\r\n charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nhello\r\n");
    }

    #[test]
    fn finds_signed_parts() {
        let body = b"preamble\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b\r\nContent-Type: application/pkcs7-signature\r\n\r\nSIG\r\n--b--\r\n";
        let (c, s) = signed_parts(body, "b").unwrap();
        assert_eq!(c, b"Content-Type: text/plain\r\n\r\nhi");
        assert_eq!(s, b"Content-Type: application/pkcs7-signature\r\n\r\nSIG");
        assert_eq!(&*canonical(b"a\nb\r\nc\n"), b"a\r\nb\r\nc\r\n");
    }
}
