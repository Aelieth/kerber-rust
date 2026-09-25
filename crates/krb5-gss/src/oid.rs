//! GSS OIDs and token framing (`generic/oid_ops.c`, `generic/util_token.c`):
//! Kerberos and SPNEGO mechanism OIDs, `GSS_C_*` flags, and the
//! RFC 2743 application token wrap.

use super::Error;

/// ISO OID 1.2.840.113554.1.2.2 (Kerberos V5 GSS).
pub const KRB5_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// SPNEGO OID 1.3.6.1.5.5.2.
pub const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// RFC 4121 checksum type in the AP-REQ authenticator (`0x8003`).
pub const GSS_CHECKSUM_TYPE: i32 = 0x8003;

/// RFC 4121 `GSS_C_DELEG_FLAG`.
pub const GSS_C_DELEG: u32 = 1;

/// RFC 2744 `GSS_C_MUTUAL_FLAG`.
pub const GSS_C_MUTUAL: u32 = 2;

/// RFC 2744 `GSS_C_REPLAY_FLAG`.
pub const GSS_C_REPLAY: u32 = 4;

/// RFC 2744 `GSS_C_SEQUENCE_FLAG`.
pub const GSS_C_SEQUENCE: u32 = 8;

/// RFC 2744 `GSS_C_CONF_FLAG`.
pub const GSS_C_CONF: u32 = 16;

/// RFC 2744 `GSS_C_INTEG_FLAG`.
pub const GSS_C_INTEG: u32 = 32;

/// RFC 2744 `GSS_C_PROT_READY_FLAG` (per-message protection available).
pub const GSS_C_PROT_READY: u32 = 128;

/// RFC 2744 `GSS_C_TRANS_FLAG` (context is exportable).
pub const GSS_C_TRANS: u32 = 256;

/// GSS_C_CHANNEL_BOUND_FLAG (`gssapi_ext.h`).
pub const GSS_C_CHANNEL_BOUND: u32 = 0x0800;

/// GSS_C_DCE_STYLE (`gssapi_ext.h`).
pub const GSS_C_DCE: u32 = 0x1000;

/// GSS_C_IDENTIFY_FLAG.
pub const GSS_C_IDENTIFY: u32 = 0x2000;

/// GSS_C_EXTENDED_ERROR_FLAG.
pub const GSS_C_EXTENDED_ERROR: u32 = 0x4000;

/// RFC 4121 per-message tokens are bare (no RFC 2743 APPLICATION 0 wrapper).
pub(super) fn message_token(token: &[u8]) -> Result<Vec<u8>, Error> {
    if token.first() == Some(&0x60) {
        gss_unwrap_app(token)
    } else {
        Ok(token.to_vec())
    }
}

pub(super) fn gss_wrap_app(tok_id: [u8; 2], inner: &[u8]) -> Vec<u8> {
    let mut body = der_tlv(0x06, KRB5_OID);
    body.extend_from_slice(&tok_id);
    body.extend_from_slice(inner);
    der_tlv(0x60, &body)
}

pub(super) fn gss_unwrap_app(token: &[u8]) -> Result<Vec<u8>, Error> {
    if token.len() < 2 || token[0] != 0x60 {
        return Err(Error::Truncated);
    }
    let (hlen, blen) = der_len_decode(&token[1..])?;
    let start = 1 + hlen;
    if start + blen > token.len() {
        return Err(Error::Truncated);
    }
    let body = &token[start..start + blen];
    if body.len() < 2 || body[0] != 0x06 {
        return Err(Error::Truncated);
    }
    let oid_len = usize::from(body[1]);
    let rest = body.get(2 + oid_len..).ok_or(Error::Truncated)?;
    Ok(rest.to_vec())
}

pub(super) fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

fn der_len(out: &mut Vec<u8>, n: usize) {
    if let Ok(b) = u8::try_from(n) {
        if b < 128 {
            out.push(b);
        } else {
            out.push(0x81);
            out.push(b);
        }
        return;
    }
    out.push(0x82);
    out.extend_from_slice(&(u16::try_from(n).unwrap_or(u16::MAX)).to_be_bytes());
}

pub(super) fn der_len_decode(b: &[u8]) -> Result<(usize, usize), Error> {
    if b.is_empty() {
        return Err(Error::Truncated);
    }
    if b[0] < 128 {
        return Ok((1, usize::from(b[0])));
    }
    if b[0] == 0x81 && b.len() >= 2 {
        return Ok((2, usize::from(b[1])));
    }
    if b[0] == 0x82 && b.len() >= 3 {
        return Ok((3, usize::from(u16::from_be_bytes([b[1], b[2]]))));
    }
    Err(Error::Truncated)
}
