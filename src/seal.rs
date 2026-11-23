//! Authenticated encryption for cookies. The session, including the mail
//! password, exists only inside the browser's HttpOnly cookie, sealed with a
//! key that never leaves this server. Nothing about a session is written to disk.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Serialize, de::DeserializeOwned};
use std::{io::Write, path::Path};

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("operating system random source");
    b
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct Sealer {
    cipher: XChaCha20Poly1305,
}

impl Sealer {
    pub fn new(key: &[u8; 32]) -> Self {
        Sealer {
            cipher: XChaCha20Poly1305::new_from_slice(key).expect("32-byte key"),
        }
    }

    /// Loads the key from `POSTERN_SECRET_KEY` (64 hex characters) or from
    /// `secret.key` in the data directory, creating that file on first start.
    pub fn load(data_dir: &Path) -> Result<Self, String> {
        if let Ok(v) = std::env::var("POSTERN_SECRET_KEY") {
            if !v.trim().is_empty() {
                let bytes = unhex(&v)
                    .filter(|b| b.len() == 32)
                    .ok_or("POSTERN_SECRET_KEY must be 64 hex characters")?;
                return Ok(Self::new(&bytes.try_into().unwrap()));
            }
        }
        let path = data_dir.join("secret.key");
        match std::fs::read_to_string(&path) {
            // An empty file holds no key. A first start that ran out of disk
            // space can leave one behind, so it is replaced, not refused.
            Ok(text) if text.trim().is_empty() => Self::create_key(&path),
            Ok(text) => {
                let bytes = unhex(&text)
                    .filter(|b| b.len() == 32)
                    .ok_or_else(|| format!("{} is not a valid key file", path.display()))?;
                Ok(Self::new(&bytes.try_into().unwrap()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::create_key(&path),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }

    /// Writes a new key next to `path` and renames it into place, so a failed
    /// write (full disk) never leaves a half-written key file.
    fn create_key(path: &Path) -> Result<Self, String> {
        let key: [u8; 32] = random_bytes();
        let tmp = path.with_extension("key.tmp");
        let _ = std::fs::remove_file(&tmp);
        let write = || -> std::io::Result<()> {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(hex(&key).as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        };
        if let Err(e) = write() {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("cannot write {}: {e}", path.display()));
        }
        tracing::info!("created new sealing key at {}", path.display());
        Ok(Self::new(&key))
    }

    /// Encrypts `value`. `context` is bound in, so a value sealed for one
    /// purpose cannot be replayed for another.
    pub fn seal<T: Serialize>(&self, context: &str, value: &T) -> String {
        let nonce: [u8; 24] = random_bytes();
        let plain = serde_json::to_vec(value).expect("serializable");
        let ct = self
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: context.as_bytes(),
                },
            )
            .expect("encryption");
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        B64.encode(out)
    }

    pub fn open<T: DeserializeOwned>(&self, context: &str, sealed: &str) -> Option<T> {
        let raw = B64.decode(sealed.trim()).ok()?;
        if raw.len() < 24 + 16 {
            return None;
        }
        let (nonce, ct) = raw.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().ok()?;
        let plain = self
            .cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ct,
                    aad: context.as_bytes(),
                },
            )
            .ok()?;
        serde_json::from_slice(&plain).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct S {
        user: String,
        pass: String,
    }

    #[test]
    fn key_file_survives_a_failed_first_start() {
        let dir = std::env::temp_dir().join(format!("postern-key-{}", hex(&random_bytes::<8>())));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.key");
        // What a full disk used to leave behind: an empty file.
        std::fs::write(&path, "").unwrap();
        Sealer::load(&dir).expect("empty key file is replaced");
        let first = std::fs::read_to_string(&path).unwrap();
        assert_eq!(first.len(), 64);
        assert!(!dir.join("secret.key.tmp").exists());
        // A second start keeps the key.
        Sealer::load(&dir).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
        // Anything else that is not a key is still refused, never overwritten.
        std::fs::write(&path, "not a key").unwrap();
        assert!(Sealer::load(&dir).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a key");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn sample() -> S {
        S {
            user: "a@example.com".into(),
            pass: "p\u{e4}ss w\u{f6}rd \"\\".into(),
        }
    }

    #[test]
    fn roundtrip() {
        let s = Sealer::new(&[7u8; 32]);
        let c = s.seal("session", &sample());
        assert_eq!(s.open::<S>("session", &c), Some(sample()));
        assert!(!c.contains("example"));
    }

    #[test]
    fn two_seals_differ() {
        let s = Sealer::new(&[7u8; 32]);
        assert_ne!(s.seal("session", &sample()), s.seal("session", &sample()));
    }

    #[test]
    fn rejects_wrong_key_context_and_tampering() {
        let s = Sealer::new(&[7u8; 32]);
        let c = s.seal("session", &sample());
        assert!(Sealer::new(&[8u8; 32]).open::<S>("session", &c).is_none());
        assert!(s.open::<S>("admin", &c).is_none());
        let mut raw = B64.decode(&c).unwrap();
        for i in [0usize, 10, 24, raw.len() - 1] {
            raw[i] ^= 1;
            assert!(s.open::<S>("session", &B64.encode(&raw)).is_none());
            raw[i] ^= 1;
        }
        assert!(s.open::<S>("session", &c[..c.len() - 4]).is_none());
        assert!(s.open::<S>("session", "").is_none());
        assert!(s.open::<S>("session", "not base64 !!").is_none());
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(
            unhex(&hex(&[0, 1, 254, 255])).unwrap(),
            vec![0, 1, 254, 255]
        );
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }
}
