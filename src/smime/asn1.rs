//! Just enough ASN.1 for CMS: a reader that accepts BER (indefinite lengths,
//! chunked strings, as Outlook and Thunderbird write it) and a DER writer.
//!
//! The reader never copies except to join chunked strings, keeps the raw bytes
//! of every element (signatures are checked over those), and refuses nesting
//! deeper than [`MAX_DEPTH`].

use std::borrow::Cow;

pub const MAX_DEPTH: usize = 48;

#[derive(Debug)]
pub struct Asn1Error(#[allow(dead_code)] pub &'static str);

pub type R<T> = std::result::Result<T, Asn1Error>;

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;
pub const OCTET_STRING_C: u8 = 0x24;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;

/// One element: its tag byte, the bytes it occupies and its content.
#[derive(Clone, Copy, Debug)]
pub struct Node<'a> {
    pub tag: u8,
    /// The whole element, header included (and the end marker if indefinite).
    pub raw: &'a [u8],
    /// The content, without the end marker.
    pub content: &'a [u8],
    depth: usize,
}

/// Reads one element from the front of `input`; returns it and what follows.
pub fn read(input: &[u8]) -> R<(Node<'_>, &[u8])> {
    read_at(input, 0)
}

/// Reads exactly one element; trailing bytes other than zero padding are an error.
pub fn read_all(input: &[u8]) -> R<Node<'_>> {
    let (n, rest) = read(input)?;
    if rest.iter().any(|b| *b != 0) {
        return Err(Asn1Error("trailing data"));
    }
    Ok(n)
}

fn read_at(input: &[u8], depth: usize) -> R<(Node<'_>, &[u8])> {
    if depth > MAX_DEPTH {
        return Err(Asn1Error("nested too deeply"));
    }
    let tag = *input.first().ok_or(Asn1Error("truncated"))?;
    if tag & 0x1f == 0x1f {
        return Err(Asn1Error("high tag numbers are not used in CMS"));
    }
    let first = *input.get(1).ok_or(Asn1Error("truncated"))?;
    let mut pos = 2usize;
    if first == 0x80 {
        // Indefinite length: only for constructed elements; content runs to 00 00.
        if tag & 0x20 == 0 {
            return Err(Asn1Error("indefinite length on a primitive"));
        }
        let mut rest = &input[pos..];
        loop {
            if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                let content_len = input.len() - pos - rest.len();
                let end = pos + content_len + 2;
                return Ok((
                    Node {
                        tag,
                        raw: &input[..end],
                        content: &input[pos..pos + content_len],
                        depth,
                    },
                    &input[end..],
                ));
            }
            let (_, after) = read_at(rest, depth + 1)?;
            rest = after;
        }
    }
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(Asn1Error("unsupported length"));
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | *input.get(pos).ok_or(Asn1Error("truncated"))? as usize;
            pos += 1;
        }
        len
    };
    let end = pos.checked_add(len).ok_or(Asn1Error("length overflow"))?;
    if end > input.len() {
        return Err(Asn1Error("truncated"));
    }
    Ok((
        Node {
            tag,
            raw: &input[..end],
            content: &input[pos..end],
            depth,
        },
        &input[end..],
    ))
}

impl<'a> Node<'a> {
    pub fn constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    /// The child elements of a constructed element.
    pub fn children(&self) -> R<Vec<Node<'a>>> {
        if !self.constructed() {
            return Err(Asn1Error("not constructed"));
        }
        let mut out = Vec::new();
        let mut rest = self.content;
        while !rest.is_empty() {
            let (n, after) = read_at(rest, self.depth + 1)?;
            out.push(n);
            rest = after;
            if out.len() > 10_000 {
                return Err(Asn1Error("too many elements"));
            }
        }
        Ok(out)
    }

    pub fn expect(self, tag: u8) -> R<Self> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(Asn1Error("unexpected element"))
        }
    }

    /// The bytes of a string type, joining the chunks of a constructed one.
    pub fn octets(&self) -> R<Cow<'a, [u8]>> {
        if !self.constructed() {
            return Ok(Cow::Borrowed(self.content));
        }
        let mut out = Vec::new();
        for c in self.children()? {
            out.extend_from_slice(&c.octets()?);
        }
        Ok(Cow::Owned(out))
    }

    pub fn oid(&self) -> R<&'a [u8]> {
        if self.tag != OID {
            return Err(Asn1Error("expected an object identifier"));
        }
        Ok(self.content)
    }

    /// A small non-negative INTEGER, such as a version number.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn small_int(&self) -> R<u64> {
        if self.tag != INTEGER || self.content.is_empty() || self.content.len() > 8 {
            return Err(Asn1Error("expected a small integer"));
        }
        if self.content[0] & 0x80 != 0 {
            return Err(Asn1Error("negative integer"));
        }
        Ok(self.content.iter().fold(0u64, |n, b| (n << 8) | *b as u64))
    }
}

// ---- object identifiers ----------------------------------------------------

/// The content bytes of an OID written in dotted form.
pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
    let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut stack = vec![(a & 0x7f) as u8];
        let mut v = a >> 7;
        while v > 0 {
            stack.push((v & 0x7f) as u8 | 0x80);
            v >>= 7;
        }
        out.extend(stack.iter().rev());
    }
    out
}

pub fn oid_is(bytes: &[u8], dotted: &str) -> bool {
    bytes == oid(dotted).as_slice()
}

// ---- writer ----------------------------------------------------------------

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = n.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

/// A DER SET OF: the elements sorted by their encoding.
pub fn set_of(mut items: Vec<Vec<u8>>) -> Vec<u8> {
    items.sort();
    tlv(SET, &items.concat())
}

pub fn oid_tlv(dotted: &str) -> Vec<u8> {
    tlv(OID, &oid(dotted))
}

pub fn small_int_tlv(n: u8) -> Vec<u8> {
    if n & 0x80 != 0 {
        tlv(INTEGER, &[0, n])
    } else {
        tlv(INTEGER, &[n])
    }
}

pub fn octet_string(b: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, b)
}

pub fn null() -> Vec<u8> {
    vec![NULL, 0]
}

/// AlgorithmIdentifier with absent or NULL parameters.
pub fn alg(dotted: &str, with_null: bool) -> Vec<u8> {
    if with_null {
        seq(&[&oid_tlv(dotted), &null()])
    } else {
        seq(&[&oid_tlv(dotted)])
    }
}

/// Replaces the tag byte of an encoded element (for IMPLICIT tagging).
pub fn retag(mut der: Vec<u8>, tag: u8) -> Vec<u8> {
    if let Some(b) = der.first_mut() {
        *b = tag;
    }
    der
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_encoding() {
        assert_eq!(oid("1.2.840.113549.1.7.2"), [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);
        assert_eq!(oid("2.16.840.1.101.3.4.1.42"), [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a]);
    }

    #[test]
    fn reads_ber_with_chunks_and_indefinite_lengths() {
        // SEQUENCE (indefinite) { OCTET STRING (constructed, indefinite) { "ab", "cd" }, INTEGER 5 }
        let ber = [
            0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x02, b'c', b'd', 0x00, 0x00,
            0x02, 0x01, 0x05, 0x00, 0x00,
        ];
        let n = read_all(&ber).unwrap();
        let kids = n.children().unwrap();
        assert_eq!(kids.len(), 2);
        assert_eq!(&*kids[0].octets().unwrap(), b"abcd");
        assert_eq!(kids[1].small_int().unwrap(), 5);
    }

    #[test]
    fn writer_round_trip() {
        let long = vec![7u8; 300];
        let der = seq(&[&octet_string(&long), &small_int_tlv(200)]);
        let n = read_all(&der).unwrap();
        let kids = n.children().unwrap();
        assert_eq!(&*kids[0].octets().unwrap(), &long[..]);
        assert_eq!(kids[1].small_int().unwrap(), 200);
    }

    #[test]
    fn refuses_garbage() {
        assert!(read_all(&[0x30, 0x05, 0x01]).is_err());
        assert!(read_all(&[0x04, 0x80, 0x00, 0x00]).is_err());
        assert!(read_all(&[0x30, 0x85, 1, 2, 3, 4, 5]).is_err());
        let mut deep = Vec::new();
        for _ in 0..100 {
            deep.extend_from_slice(&[0x30, 0x80]);
        }
        assert!(read_all(&deep).is_err());
    }
}
