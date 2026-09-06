//! KRB-SAFE body DER the encoder would normalise (MIT `rd_safe.c`).

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum};
use krb5_protocol::{ReplayCache, build_krb_safe_ex, unwrap_krb_safe};
use krb5_types::ku;

fn session() -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32]).unwrap()
}

fn take(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let b = *input.get(1)?;
    let (ln, hdr) = if b < 0x80 {
        (b as usize, 1usize)
    } else {
        let nbytes = (b & 0x7f) as usize;
        if nbytes == 0 || nbytes > 4 || 2 + nbytes > input.len() {
            return None;
        }
        let mut n = 0usize;
        for i in 0..nbytes {
            n = (n << 8) | usize::from(*input.get(2 + i)?);
        }
        (n, 1 + nbytes)
    };
    let start = 1 + hdr;
    let end = start.checked_add(ln)?;
    Some((tag, input.get(start..end)?, input.get(end..)?))
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let n = content.len();
    let mut out = vec![tag];
    if let Ok(b) = u8::try_from(n)
        && b < 0x80
    {
        out.push(b);
    } else {
        let b = n.to_be_bytes();
        let start = b.iter().position(|x| *x != 0).unwrap_or(b.len() - 1);
        let raw = &b[start..];
        out.push(0x80 | u8::try_from(raw.len()).unwrap_or(8));
        out.extend_from_slice(raw);
    }
    out.extend_from_slice(content);
    out
}

fn expand_int(der: &[u8]) -> Vec<u8> {
    let (tag, inner, _) = take(der).expect("INTEGER");
    assert_eq!(tag, 0x02);
    let mut bytes = vec![0u8];
    bytes.extend_from_slice(inner);
    tlv(0x02, &bytes)
}

fn expand_seq_integer(safe: &[u8]) -> Vec<u8> {
    let (app, app_inner, _) = take(safe).expect("APPLICATION");
    let (seqt, seq, _) = take(app_inner).expect("SEQUENCE");
    let mut rebuilt = Vec::new();
    let mut rest = seq;
    while !rest.is_empty() {
        let (tag, inner, next) = take(rest).expect("field");
        rest = next;
        if tag & 0x1f == 2 {
            let (bseqt, bseq, _) = take(inner).expect("SAFE-BODY");
            let mut body = Vec::new();
            let mut brest = bseq;
            while !brest.is_empty() {
                let (btag, binner, bnext) = take(brest).expect("body field");
                brest = bnext;
                if btag & 0x1f == 3 {
                    body.extend(tlv(btag, &expand_int(binner)));
                } else {
                    body.extend(tlv(btag, binner));
                }
            }
            rebuilt.extend(tlv(tag, &tlv(bseqt, &body)));
        } else {
            rebuilt.extend(tlv(tag, inner));
        }
    }
    tlv(app, &tlv(seqt, &rebuilt))
}

fn body_der(safe: &[u8]) -> Vec<u8> {
    let (_, app, _) = take(safe).expect("APPLICATION");
    let (_, seq, _) = take(app).expect("SEQUENCE");
    let mut rest = seq;
    while !rest.is_empty() {
        let (tag, inner, next) = take(rest).expect("field");
        rest = next;
        if tag & 0x1f == 2 {
            return inner.to_vec();
        }
    }
    panic!("missing KRB-SAFE-BODY");
}

fn replace_cksum(safe: &[u8], mac: &[u8]) -> Vec<u8> {
    let (app, app_inner, _) = take(safe).expect("APPLICATION");
    let (seqt, seq, _) = take(app_inner).expect("SEQUENCE");
    let mut rebuilt = Vec::new();
    let mut rest = seq;
    while !rest.is_empty() {
        let (tag, inner, next) = take(rest).expect("field");
        rest = next;
        if tag & 0x1f == 3 {
            let (cst, cseq, _) = take(inner).expect("Checksum");
            let mut cfields = Vec::new();
            let mut crest = cseq;
            while !crest.is_empty() {
                let (ctag, cinner, cnext) = take(crest).expect("cksum field");
                crest = cnext;
                if ctag & 0x1f == 1 {
                    cfields.extend(tlv(ctag, &tlv(0x04, mac)));
                } else {
                    cfields.extend(tlv(ctag, cinner));
                }
            }
            rebuilt.extend(tlv(tag, &tlv(cst, &cfields)));
        } else {
            rebuilt.extend(tlv(tag, inner));
        }
    }
    tlv(app, &tlv(seqt, &rebuilt))
}

#[test]
fn accept_noncanonical_seq_integer_body() {
    let key = session();
    let msg = build_krb_safe_ex(&key, b"safe-noncanon", Some(1), true).unwrap();
    let raw = encode(&msg).unwrap();
    let expanded = expand_seq_integer(&raw);
    assert_ne!(expanded, raw);
    let body = body_der(&expanded);
    let usage = KeyUsage::new(ku::KRB_SAFE_CKSUM).unwrap();
    let mac = checksum(&key, usage, &body).unwrap();
    let signed = replace_cksum(&expanded, &mac);
    let cache = ReplayCache::new();
    assert_eq!(
        unwrap_krb_safe(&key, &signed, &cache).unwrap(),
        b"safe-noncanon"
    );
}
