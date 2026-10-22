use super::Error;

pub const KRB5_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

pub const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

pub const GSS_CHECKSUM_TYPE: i32 = 0x8003;

pub const GSS_C_DELEG: u32 = 1;

pub const GSS_C_MUTUAL: u32 = 2;

pub const GSS_C_REPLAY: u32 = 4;

pub const GSS_C_SEQUENCE: u32 = 8;

pub const GSS_C_CONF: u32 = 16;

pub const GSS_C_INTEG: u32 = 32;

pub const GSS_C_PROT_READY: u32 = 128;

pub const GSS_C_TRANS: u32 = 256;

pub const GSS_C_CHANNEL_BOUND: u32 = 0x0800;

pub const GSS_C_DCE: u32 = 0x1000;

pub const GSS_C_AF_INET: u32 = 2;

pub const GSS_C_IDENTIFY: u32 = 0x2000;

pub const GSS_C_EXTENDED_ERROR: u32 = 0x4000;

/// RFC 4121 per-message tokens are bare, with no RFC 2743 APPLICATION 0 wrapper.
pub(super) fn message_token(token: &[u8]) -> Result<Vec<u8>, Error> {
    if token.first() == Some(&0x60) {
        gss_unwrap_app(token)
    } else {
        Ok(token.to_vec())
    }
}

// MIT g_make_token_header; see docs/parity/b1-gss.md
pub(super) fn gss_wrap_app(tok_id: [u8; 2], inner: &[u8]) -> Vec<u8> {
    let mut body = der_tlv(0x06, KRB5_OID);
    body.extend_from_slice(&tok_id);
    body.extend_from_slice(inner);
    der_tlv(0x60, &body)
}

// MIT g_verify_token_header; see docs/parity/b1-gss.md
pub(super) fn gss_unwrap_app(token: &[u8]) -> Result<Vec<u8>, Error> {
    if token.len() < 2 || token[0] != 0x60 {
        return Err(Error::Truncated);
    }
    let (hlen, blen) = der_len_decode(&token[1..])?;
    let start = 1 + hlen;
    if start.checked_add(blen) != Some(token.len()) {
        return Err(Error::Truncated);
    }
    let body = &token[start..];
    if body.first() != Some(&0x06) {
        return Err(Error::Truncated);
    }
    let (olen, oid_len) = der_len_decode(&body[1..])?;
    let rest = body.get(1 + olen + oid_len..).ok_or(Error::Truncated)?;
    Ok(rest.to_vec())
}

pub(super) fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + krb5_types::der::len_len(body.len()) + body.len());
    krb5_types::der::push_tlv(&mut out, tag, body);
    out
}

pub(super) fn der_len_decode(b: &[u8]) -> Result<(usize, usize), Error> {
    krb5_types::der::read_len(b)
        .map(|(len, hlen)| (hlen, len))
        .ok_or(Error::Truncated)
}
