//! SPNEGO (`spnego/spnego_mech.c`): NegTokenInit / NegTokenResp,
//! mech-list MIC, and the krb5 optimistic token.

use krb5_crypto::ProtocolKey;
use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;

use super::context::{ChannelBindings, TOK_AP_REQ};
use super::oid::{KRB5_OID, SPNEGO_OID, der_len_decode, der_tlv, gss_wrap_app};
use super::{Error, GssContext};

/// SPNEGO `NegTokenInit` wrapping a Kerberos inner token (long-form DER length).
#[must_use]
pub fn spnego_init(krb_token: &[u8]) -> Vec<u8> {
    let oid_krb = der_tlv(0x06, KRB5_OID);
    let mech_seq = der_tlv(0x30, &oid_krb);
    let mech_types = der_tlv(0xa0, &mech_seq);
    let mech_token = der_tlv(0xa2, &der_tlv(0x04, krb_token));
    let mut seq = mech_types;
    seq.extend_from_slice(&mech_token);
    let neg = der_tlv(0xa0, &der_tlv(0x30, &seq));
    let mut app = der_tlv(0x06, SPNEGO_OID);
    app.extend_from_slice(&neg);
    der_tlv(0x60, &app)
}

/// Extract the inner Kerberos GSS token from a SPNEGO or raw krb5 blob.
///
/// # Errors
///
/// Truncated input.
pub fn spnego_inner(token: &[u8]) -> Result<&[u8], Error> {
    if token.len() < 2 || token[0] != 0x60 {
        return Err(Error::Truncated);
    }
    let (hlen, blen) = der_len_decode(&token[1..])?;
    let start = 1 + hlen;
    if start + blen > token.len() {
        return Err(Error::Truncated);
    }
    let body = &token[start..start + blen];
    if body.first() != Some(&0x06) || body.len() < 2 {
        return Err(Error::Truncated);
    }
    let oid_len = usize::from(body[1]);
    let rest = body.get(2 + oid_len..).ok_or(Error::Truncated)?;
    if rest.first() == Some(&0xa0) {
        return find_mech_token(rest);
    }
    // Raw RFC 4121/2743 Kerberos token: keep the APPLICATION 0 wrapper.
    Ok(token)
}

fn find_mech_token(neg: &[u8]) -> Result<&[u8], Error> {
    let (hlen, blen) = der_len_decode(neg.get(1..).ok_or(Error::Truncated)?)?;
    let seq_start = 1 + hlen;
    let seq = neg
        .get(seq_start..seq_start + blen)
        .ok_or(Error::Truncated)?;
    let inner = if seq.first() == Some(&0x30) {
        let (ih, il) = der_len_decode(seq.get(1..).ok_or(Error::Truncated)?)?;
        seq.get(1 + ih..1 + ih + il).ok_or(Error::Truncated)?
    } else {
        seq
    };
    let mut i = 0usize;
    while i + 2 < inner.len() {
        let tag = inner[i];
        let (lh, ln) = der_len_decode(&inner[i + 1..])?;
        let body_at = i + 1 + lh;
        let body = inner.get(body_at..body_at + ln).ok_or(Error::Truncated)?;
        if tag == 0xa2 {
            if body.first() == Some(&0x04) {
                let (oh, ol) = der_len_decode(body.get(1..).ok_or(Error::Truncated)?)?;
                return body.get(1 + oh..1 + oh + ol).ok_or(Error::Truncated);
            }
            return Ok(body);
        }
        i = body_at + ln;
    }
    Err(Error::Truncated)
}

const SPNEGO_ACCEPT_COMPLETED: u8 = 0;

fn der_oid(oid: &[u8]) -> Vec<u8> {
    der_tlv(0x06, oid)
}

fn der_octet(b: &[u8]) -> Vec<u8> {
    der_tlv(0x04, b)
}

fn der_enumerated(v: u8) -> Vec<u8> {
    vec![0x0a, 0x01, v]
}

fn parse_octet(body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.first() != Some(&0x04) {
        return Ok(body.to_vec());
    }
    let (h, n) = der_len_decode(body.get(1..).ok_or(Error::Truncated)?)?;
    body.get(1 + h..1 + h + n)
        .ok_or(Error::Truncated)
        .map(<[u8]>::to_vec)
}

fn gss_oid_body(token: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if token.len() < 2 || token[0] != 0x60 {
        return Err(Error::Truncated);
    }
    let (hlen, blen) = der_len_decode(&token[1..])?;
    let start = 1 + hlen;
    let body = token.get(start..start + blen).ok_or(Error::Truncated)?;
    if body.first() != Some(&0x06) || body.len() < 2 {
        return Err(Error::Truncated);
    }
    let oid_len = usize::from(body[1]);
    let oid = body.get(2..2 + oid_len).ok_or(Error::Truncated)?;
    let rest = body.get(2 + oid_len..).ok_or(Error::Truncated)?;
    Ok((oid, rest))
}

/// Whether `token` is a GSS-wrapped SPNEGO NegotiationToken.
#[must_use]
pub fn is_spnego(token: &[u8]) -> bool {
    matches!(gss_oid_body(token), Ok((oid, _)) if oid == SPNEGO_OID)
}

pub(super) struct NegInit {
    mech_list_der: Vec<u8>,
    mech_token: Vec<u8>,
    mic: Option<Vec<u8>>,
}

/// MIT `get_negTokenInit` (`spnego_mech.c:3427-3430`): a token whose header is not SPNEGO is defective and is not a negotiation.
/// A length that runs past the token is not a mechanism list or a mechanism token.
pub(super) fn parse_neg_init(token: &[u8]) -> Result<NegInit, Error> {
    let (oid, rest) = gss_oid_body(token)?;
    if oid != SPNEGO_OID {
        return Err(Error::Truncated);
    }
    if rest.first() != Some(&0xa0) {
        return Err(Error::Truncated);
    }
    let (h, n) = der_len_decode(rest.get(1..).ok_or(Error::Truncated)?)?;
    let inner = rest.get(1 + h..1 + h + n).ok_or(Error::Truncated)?;
    let seq = if inner.first() == Some(&0x30) {
        let (sh, sn) = der_len_decode(inner.get(1..).ok_or(Error::Truncated)?)?;
        inner.get(1 + sh..1 + sh + sn).ok_or(Error::Truncated)?
    } else {
        inner
    };
    let mut mech_list_der = None;
    let mut mech_token = None;
    let mut mic = None;
    let mut i = 0usize;
    while i < seq.len() {
        let tag = seq[i];
        let (lh, ln) = der_len_decode(seq.get(i + 1..).ok_or(Error::Truncated)?)?;
        let body = seq
            .get(i + 1 + lh..i + 1 + lh + ln)
            .ok_or(Error::Truncated)?;
        match tag {
            0xa0 => {
                if mech_list_der.is_some() {
                    return Err(Error::Truncated);
                }
                mech_list_der = Some(body.to_vec());
            }
            0xa2 => {
                if mech_token.is_some() {
                    return Err(Error::Truncated);
                }
                mech_token = Some(parse_octet(body)?);
            }
            0xa3 => {
                if mic.is_some() {
                    return Err(Error::Truncated);
                }
                mic = Some(parse_octet(body)?);
            }
            _ => {}
        }
        i = i.saturating_add(1).saturating_add(lh).saturating_add(ln);
    }
    Ok(NegInit {
        mech_list_der: mech_list_der.ok_or(Error::Truncated)?,
        mech_token: mech_token.ok_or(Error::Truncated)?,
        mic,
    })
}

fn mech_list_has_krb5(list: &[u8]) -> Result<bool, Error> {
    let seq = if list.first() == Some(&0x30) {
        let (h, n) = der_len_decode(list.get(1..).ok_or(Error::Truncated)?)?;
        list.get(1 + h..1 + h + n).ok_or(Error::Truncated)?
    } else {
        list
    };
    let mut i = 0usize;
    let mut found = false;
    while i < seq.len() {
        let tag = seq[i];
        let (lh, ln) = der_len_decode(seq.get(i + 1..).ok_or(Error::Truncated)?)?;
        let body = seq
            .get(i + 1 + lh..i + 1 + lh + ln)
            .ok_or(Error::Truncated)?;
        if tag == 0x06 && body == KRB5_OID {
            found = true;
        }
        i = i.saturating_add(1).saturating_add(lh).saturating_add(ln);
    }
    Ok(found)
}

fn encode_neg_resp(state: u8, mech: &[u8], response: Option<&[u8]>, mic: Option<&[u8]>) -> Vec<u8> {
    let mut seq = der_tlv(0xa0, &der_enumerated(state));
    seq.extend_from_slice(&der_tlv(0xa1, &der_oid(mech)));
    if let Some(r) = response {
        seq.extend_from_slice(&der_tlv(0xa2, &der_octet(r)));
    }
    if let Some(m) = mic {
        seq.extend_from_slice(&der_tlv(0xa3, &der_octet(m)));
    }
    der_tlv(0xa1, &der_tlv(0x30, &seq))
}

fn mech_token_as_gss(mech_token: &[u8]) -> Vec<u8> {
    if mech_token.first() == Some(&0x60) {
        mech_token.to_vec()
    } else {
        gss_wrap_app(TOK_AP_REQ, mech_token)
    }
}

/// SPNEGO acceptor: `NegTokenInit` → krb5 accept → `NegTokenResp` with MIC.
///
/// A `mechListMIC` on the init token is verified here. A follow-up
/// `NegTokenResp` MIC from the initiator (RFC 4178 second-leg) is **not**
/// consumed by this call; the acceptor must pass that token to
/// [`GssContext::verify_spnego_mic`] after the context is established.
///
/// # Errors
///
/// Truncated SPNEGO, AP-REQ verify, or MIC verify.
pub fn spnego_accept(
    token: &[u8],
    service_keys: &[ProtocolKey],
    channel_bindings: Option<&ChannelBindings>,
    expected_server: Option<&PrincipalName>,
    expected_realm: Option<&str>,
    rcache: &ReplayCache,
) -> Result<(GssContext, Vec<u8>), Error> {
    spnego_accept_kt(
        token,
        service_keys,
        None,
        channel_bindings,
        expected_server,
        expected_realm,
        rcache,
    )
}

/// [`spnego_accept`] with a per-key kvno slice; see
/// [`GssContext::accept_sec_context_kt`] for the kvno-pinning semantics.
///
/// # Errors
///
/// Truncated SPNEGO, AP-REQ verify, or MIC verify.
pub fn spnego_accept_kt(
    token: &[u8],
    service_keys: &[ProtocolKey],
    service_kvnos: Option<&[u32]>,
    channel_bindings: Option<&ChannelBindings>,
    expected_server: Option<&PrincipalName>,
    expected_realm: Option<&str>,
    rcache: &ReplayCache,
) -> Result<(GssContext, Vec<u8>), Error> {
    let init = parse_neg_init(token)?;
    if !mech_list_has_krb5(&init.mech_list_der)? {
        return Err(Error::Truncated);
    }
    let mech = mech_token_as_gss(&init.mech_token);
    let (mut ctx, ap_rep) = GssContext::accept_sec_context_kt(
        &mech,
        service_keys,
        service_kvnos,
        channel_bindings,
        expected_server,
        expected_realm,
        rcache,
    )?;
    if let Some(mic) = &init.mic {
        ctx.verify_mic(&init.mech_list_der, mic)?;
    }
    let mic = ctx.get_mic(&init.mech_list_der)?;
    ctx.spnego_mech_list = Some(init.mech_list_der);
    let resp = encode_neg_resp(
        SPNEGO_ACCEPT_COMPLETED,
        KRB5_OID,
        ap_rep.as_deref(),
        Some(&mic),
    );
    Ok((ctx, resp))
}

fn parse_neg_resp_mic(token: &[u8]) -> Result<Vec<u8>, Error> {
    let rest = if token.first() == Some(&0xa1) {
        token
    } else {
        return Err(Error::Truncated);
    };
    let (h, n) = der_len_decode(rest.get(1..).ok_or(Error::Truncated)?)?;
    let inner = rest.get(1 + h..1 + h + n).ok_or(Error::Truncated)?;
    let seq = if inner.first() == Some(&0x30) {
        let (sh, sn) = der_len_decode(inner.get(1..).ok_or(Error::Truncated)?)?;
        inner.get(1 + sh..1 + sh + sn).ok_or(Error::Truncated)?
    } else {
        inner
    };
    let mut i = 0usize;
    while i < seq.len() {
        let tag = seq[i];
        let (lh, ln) = der_len_decode(seq.get(i + 1..).ok_or(Error::Truncated)?)?;
        let body = seq
            .get(i + 1 + lh..i + 1 + lh + ln)
            .ok_or(Error::Truncated)?;
        if tag == 0xa3 {
            return parse_octet(body);
        }
        i = i.saturating_add(1).saturating_add(lh).saturating_add(ln);
    }
    Err(Error::Truncated)
}

impl GssContext {
    /// Verify a follow-up SPNEGO `NegTokenResp` mechListMIC.
    ///
    /// # Errors
    ///
    /// Truncated token or MIC verify.
    pub fn verify_spnego_mic(&mut self, token: &[u8]) -> Result<(), Error> {
        let list = self.spnego_mech_list.clone().ok_or(Error::Truncated)?;
        let mic = parse_neg_resp_mic(token)?;
        self.verify_mic(&list, &mic)
    }
}
